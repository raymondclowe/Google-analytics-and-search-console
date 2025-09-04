#!/usr/bin/env python3
"""
MCP Server for Google Analytics 4 and Search Console Data
Designed for AI model access with tools for querying GA4 and GSC data.
"""

import asyncio
import re
import logging
import json
import pandas as pd
import secrets
import hmac
import hashlib
import time
import uuid
import warnings
from typing import Dict, Optional, List, Union
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP
from datetime import datetime
from mcp_auth import extract_keys_from_request, determine_token, strip_key_param_from_scope
import concurrent.futures

# Suppress Google API warnings about file_cache and oauth2client
warnings.filterwarnings('ignore', message='file_cache is only supported with oauth2client')

# Import our existing modules
import GA4query3
import NewDownloads
from NewDownloads import async_persistent_cache


# Configure enhanced logging with structured format, and set level based on DEBUG_MODE env
import os
log_level = os.environ.get("DEBUG_MODE", "false").lower()
if log_level == "true":
    logging_level = logging.DEBUG
else:
    logging_level = logging.INFO
logging.basicConfig(
    level=logging_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Request tracking and performance monitoring
class RequestTracker:
    """Track requests for monitoring and observability"""
    
    def __init__(self):
        self.active_requests: Dict[str, Dict] = {}
        self.request_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'auth_failures': 0,
            'avg_response_time': 0.0
        }
    
    def start_request(self, request_id: str, client_ip: str, method: str, path: str) -> Dict:
        """Start tracking a new request"""
        request_info = {
            'request_id': request_id,
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'start_time': time.time(),
            'status': 'active'
        }
        self.active_requests[request_id] = request_info
        self.request_stats['total_requests'] += 1
        return request_info
    
    def end_request(self, request_id: str, status_code: int, error: Optional[str] = None):
        """End tracking for a request"""
        if request_id in self.active_requests:
            request_info = self.active_requests[request_id]
            request_info['end_time'] = time.time()
            request_info['duration'] = request_info['end_time'] - request_info['start_time']
            request_info['status_code'] = status_code
            request_info['error'] = error
            
            # Update stats
            if status_code < 400:
                self.request_stats['successful_requests'] += 1
            else:
                self.request_stats['failed_requests'] += 1
                if status_code == 401:
                    self.request_stats['auth_failures'] += 1
            
            # Update average response time
            total_time = (self.request_stats['avg_response_time'] * 
                         (self.request_stats['total_requests'] - 1) + 
                         request_info['duration'])
            self.request_stats['avg_response_time'] = total_time / self.request_stats['total_requests']
            
            del self.active_requests[request_id]
            return request_info
    
    def get_stats(self) -> Dict:
        """Get current request statistics"""
        return {
            **self.request_stats,
            'active_requests': len(self.active_requests)
        }

# Global request tracker, server start time, and middleware reference
request_tracker = RequestTracker()
start_time = time.time()
middleware = None  # Will be set when middleware is created

# Enhanced logging filter to add request context
class RequestContextFilter(logging.Filter):
    """Add request context to log records"""
    
    def filter(self, record):
        # Add request_id to log record if not present
        if not hasattr(record, 'request_id'):
            record.request_id = getattr(self, '_current_request_id', 'no-request')
        return True

# Set up the filter - only apply to our logger, not all loggers
request_filter = RequestContextFilter()

# Create a custom logger for our application that includes request context
app_logger = logging.getLogger(__name__)
app_logger.addFilter(request_filter)

def set_request_context(request_id: str):
    """Set the current request ID for logging"""
    request_filter._current_request_id = request_id

# Security utilities
def secure_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.
    Uses hmac.compare_digest directly for secure comparison of API keys.
    """
    if len(a) != len(b):
        return False
    
    # Use hmac.compare_digest directly for constant-time comparison
    return hmac.compare_digest(a.encode(), b.encode())

# Global variable to track simple mode
SIMPLE_MODE = False

# Configure FastMCP with stateless HTTP mode to avoid session ID issues
mcp = FastMCP("ga4-gsc-mcp")
# Set stateless HTTP mode to avoid session initialization issues
mcp.settings.stateless_http = True

# Helper functions
def validate_date_range(start_date: str, end_date: str) -> bool:
    """Validate date range format and logic"""
    try:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        return start <= end
    except ValueError:
        return False

def validate_ga4_dimensions_metrics(dimensions: str, metrics: str) -> dict:
    """
    Validate GA4 dimensions and metrics against common mistakes and provide suggestions.
    
    Returns:
        dict: {"valid": bool, "warnings": list, "suggestions": list}
    """
    result = {"valid": True, "warnings": [], "suggestions": []}
    
    # Common invalid dimensions and their corrections
    invalid_dimensions = {
        "sessionCampaign": "Use 'sessionCampaignId' for campaign ID or 'sessionCampaignName' for campaign name",
        "pageviews": "Use 'screenPageViews' for page view count",
        "users": "Use 'activeUsers' for current active users or 'totalUsers' for all users",
        "sessions": "sessions is a metric, not a dimension",
        "bounceRate": "bounceRate is a metric, not a dimension"
    }
    
    # Common invalid metrics and their corrections  
    invalid_metrics = {
        "pageviews": "Use 'screenPageViews' for page view count",
        "users": "Use 'activeUsers' for current active users or 'totalUsers' for all users",
        "pagePath": "pagePath is a dimension, not a metric",
        "country": "country is a dimension, not a metric"
    }
    
    # Check dimensions
    if dimensions:
        dim_list = [d.strip() for d in dimensions.split(',')]
        for dim in dim_list:
            if dim in invalid_dimensions:
                result["valid"] = False
                result["warnings"].append(f"Invalid dimension '{dim}': {invalid_dimensions[dim]}")
    
    # Check metrics
    if metrics:
        metric_list = [m.strip() for m in metrics.split(',')]
        for metric in metric_list:
            if metric in invalid_metrics:
                result["valid"] = False
                result["warnings"].append(f"Invalid metric '{metric}': {invalid_metrics[metric]}")
    
    # Add general suggestions if any issues found
    if not result["valid"]:
        result["suggestions"].extend([
            "Verify dimensions and metrics at: https://developers.google.com/analytics/devguides/reporting/data/v1/api-schema",
            "Use the 'list_ga4_properties' tool first to ensure you have access to the property",
            "Test with simple, known-valid dimensions like 'pagePath' and metrics like 'screenPageViews'"
        ])
    
    return result

def get_default_date_range(days: int = 30) -> dict:
    """Get default date range (last N days)"""
    end_date = pd.Timestamp.now()
    start_date = end_date - pd.Timedelta(days=days)
    return {
        "start_date": start_date.strftime('%Y-%m-%d'),
        "end_date": end_date.strftime('%Y-%m-%d')
    }

def add_today_date_to_response(response: dict) -> dict:
    """Add today's date to response for AI client context"""
    if isinstance(response, dict):
        response["todays_date"] = datetime.now().strftime('%Y-%m-%d')
    return response

def parse_multi_input(input_value: Union[str, List[str]]) -> List[str]:
    """
    Parse multi-property/domain input into a list.
    
    Accepts:
    - Single string: "123456789"
    - Comma-separated string: "123456789,987654321,456789123"
    - List of strings: ["123456789", "987654321", "456789123"]
    
    Returns:
    - List of strings, empty list if input is empty/None
    """
    if not input_value:
        return []
    
    if isinstance(input_value, list):
        # Already a list, filter out empty strings
        return [str(item).strip() for item in input_value if str(item).strip()]
    
    if isinstance(input_value, str):
        # Handle comma-separated string
        if ',' in input_value:
            return [item.strip() for item in input_value.split(',') if item.strip()]
        else:
            # Single string
            return [input_value.strip()] if input_value.strip() else []
    
    # Convert other types to string and treat as single item
    return [str(input_value).strip()] if str(input_value).strip() else []

async def process_multiple_properties_ga4(
    property_ids: List[str],
    start_date: str,
    end_date: str,
    auth_identifier: str,
    dimensions: str,
    metrics: str,
    debug: bool,
    max_concurrent: int = 5
) -> Dict:
    """
    Process multiple GA4 properties concurrently.
    
    Args:
        property_ids: List of GA4 property IDs
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        auth_identifier: Authentication identifier
        dimensions: Comma-separated dimensions
        metrics: Comma-separated metrics
        debug: Enable debug output
        max_concurrent: Maximum concurrent requests (default: 5)
    
    Returns:
        Dict containing aggregated results with source attribution
    """
    if not property_ids:
        return {"status": "error", "message": "No property IDs provided"}
    
    async def query_single_property(property_id: str) -> Dict:
        """Query a single GA4 property"""
        try:
            if debug:
                logger.info(f"Querying GA4 property: {property_id}")
            
            # Use asyncio to run the sync function in a thread pool
            loop = asyncio.get_event_loop()
            df = await loop.run_in_executor(
                None,
                GA4query3.produce_report,
                start_date,
                end_date,
                property_id,
                f"Property_{property_id}",
                auth_identifier,
                None,  # filter_expression
                dimensions,
                metrics,
                debug
            )
            
            if df is not None and not df.empty:
                # Add source attribution
                df['source_property_id'] = property_id
                df['source_type'] = 'ga4'
                return {
                    "property_id": property_id,
                    "status": "success",
                    "data": df,
                    "row_count": len(df)
                }
            else:
                return {
                    "property_id": property_id,
                    "status": "success",
                    "data": pd.DataFrame(),
                    "row_count": 0
                }
        except Exception as e:
            logger.error(f"Error querying GA4 property {property_id}: {str(e)}")
            return {
                "property_id": property_id,
                "status": "error",
                "error": str(e),
                "data": pd.DataFrame(),
                "row_count": 0
            }
    
    # Process properties with concurrency limit
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_query(property_id: str):
        async with semaphore:
            return await query_single_property(property_id)
    
    # Execute all queries concurrently
    tasks = [limited_query(prop_id) for prop_id in property_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Aggregate results
    all_data = []
    successful_queries = 0
    failed_queries = 0
    property_results = {}
    
    for result in results:
        if isinstance(result, Exception):
            failed_queries += 1
            continue
        
        property_id = result["property_id"]
        property_results[property_id] = {
            "status": result["status"],
            "row_count": result["row_count"],
            "error": result.get("error")
        }
        
        if result["status"] == "success" and not result["data"].empty:
            all_data.append(result["data"])
            successful_queries += 1
        elif result["status"] == "error":
            failed_queries += 1
    
    # Combine all data
    if all_data:
        combined_df = pd.concat(all_data, ignore_index=True)
        total_rows = len(combined_df)
        data_records = combined_df.to_dict('records')
    else:
        total_rows = 0
        data_records = []
    
    return {
        "status": "success" if successful_queries > 0 else "error",
        "message": f"Processed {len(property_ids)} properties: {successful_queries} successful, {failed_queries} failed",
        "data": data_records,
        "row_count": total_rows,
        "property_count": len(property_ids),
        "successful_properties": successful_queries,
        "failed_properties": failed_queries,
        "property_results": property_results
    }

async def process_multiple_domains_gsc(
    domains: List[str],
    start_date: str,
    end_date: str,
    auth_identifier: str,
    dimensions: str,
    search_type: str,
    debug: bool,
    max_concurrent: int = 5
) -> Dict:
    """
    Process multiple GSC domains concurrently.
    
    Args:
        domains: List of domain names
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        auth_identifier: Authentication identifier
        dimensions: Comma-separated dimensions
        search_type: Type of search data (web, image, video)
        debug: Enable debug output
        max_concurrent: Maximum concurrent requests (default: 5)
    
    Returns:
        Dict containing aggregated results with source attribution
    """
    if not domains:
        return {"status": "error", "message": "No domains provided"}
    
    async def query_single_domain(domain: str) -> Dict:
        """Query a single GSC domain"""
        try:
            if debug:
                logger.info(f"Querying GSC domain: {domain}")
            
            # Use the async version directly
            df = await NewDownloads.fetch_search_console_data_async(
                start_date=start_date,
                end_date=end_date,
                search_type=search_type,
                dimensions=dimensions,
                google_account=auth_identifier,
                wait_seconds=0,
                debug=debug,
                domain_filter=domain
            )
            
            if df is not None and not df.empty:
                # Add source attribution
                df['source_domain'] = domain
                df['source_type'] = 'gsc'
                return {
                    "domain": domain,
                    "status": "success",
                    "data": df,
                    "row_count": len(df)
                }
            else:
                return {
                    "domain": domain,
                    "status": "success",
                    "data": pd.DataFrame(),
                    "row_count": 0
                }
        except Exception as e:
            logger.error(f"Error querying GSC domain {domain}: {str(e)}")
            return {
                "domain": domain,
                "status": "error",
                "error": str(e),
                "data": pd.DataFrame(),
                "row_count": 0
            }
    
    # Process domains with concurrency limit
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_query(domain: str):
        async with semaphore:
            return await query_single_domain(domain)
    
    # Execute all queries concurrently
    tasks = [limited_query(domain) for domain in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Aggregate results
    all_data = []
    successful_queries = 0
    failed_queries = 0
    domain_results = {}
    
    for result in results:
        if isinstance(result, Exception):
            failed_queries += 1
            continue
        
        domain = result["domain"]
        domain_results[domain] = {
            "status": result["status"],
            "row_count": result["row_count"],
            "error": result.get("error")
        }
        
        if result["status"] == "success" and not result["data"].empty:
            all_data.append(result["data"])
            successful_queries += 1
        elif result["status"] == "error":
            failed_queries += 1
    
    # Combine all data
    if all_data:
        combined_df = pd.concat(all_data, ignore_index=True)
        total_rows = len(combined_df)
        data_records = combined_df.to_dict('records')
    else:
        total_rows = 0
        data_records = []
    
    return {
        "status": "success" if successful_queries > 0 else "error",
        "message": f"Processed {len(domains)} domains: {successful_queries} successful, {failed_queries} failed",
        "data": data_records,
        "row_count": total_rows,
        "domain_count": len(domains),
        "successful_domains": successful_queries,
        "failed_domains": failed_queries,
        "domain_results": domain_results
    }

@mcp.tool()
async def query_ga4_data(start_date: str, end_date: str, auth_identifier: str = "", property_id: Union[str, List[str]] = "", domain_filter: str = "", metrics: str = "screenPageViews,totalAdRevenue,sessions", dimensions: str = "pagePath", debug: bool = False) -> dict:
    """
    Query Google Analytics 4 data for comprehensive website analytics.
    
    Business Use Cases:
    - Track page performance and visitor engagement
    - Monitor AdSense revenue by page and traffic source
    - Analyze user behavior patterns and demographics
    - Identify top-performing content for SEO optimization
    
    ⚠️ IMPORTANT: Dimension & Metric Validation
    Only use valid GA4 dimensions and metrics. Invalid ones will cause 400 errors.
    
    📋 Commonly Used Valid Dimensions:
    - Page/Content: pagePath, pageTitle, hostname, landingPage, landingPagePlusQueryString
    - User/Session: country, city, deviceCategory, browser, operatingSystem
    - Traffic Source: sessionSource, sessionMedium, sessionSourceMedium
    - Time: date, hour, dayOfWeek, month, year
    - Custom: Use format "customEvent:parameter_name" for event-scoped custom dimensions
    
    📊 Commonly Used Valid Metrics:
    - Page Views: screenPageViews, screenPageViewsPerSession, scrolledUsers
    - Users: activeUsers, newUsers, totalUsers, sessions, sessionsPerUser
    - Engagement: userEngagementDuration, averageSessionDuration, bounceRate, engagementRate
    - Revenue: totalAdRevenue, totalRevenue, publisherAdClicks, publisherAdImpressions
    - Events: eventCount, eventCountPerUser, keyEvents
    
    🚫 Common Mistakes to Avoid:
    - ❌ sessionCampaign → ✅ sessionCampaignId or sessionCampaignName (if needed for campaigns)
    - ❌ pageviews → ✅ screenPageViews  
    - ❌ users → ✅ activeUsers or totalUsers
    - ❌ Invalid custom dimensions without proper "customEvent:" prefix
    
    📖 Full Reference: https://developers.google.com/analytics/devguides/reporting/data/v1/api-schema
    
    Example: Find top revenue-generating pages by traffic source:
    - dimensions: "pagePath,sessionSource,sessionMedium"  
    - metrics: "screenPageViews,totalAdRevenue,sessions"
    
    Multi-Property Usage Examples:
    - Single property: property_id="123456789"
    - Multiple properties as list: property_id=["123456789", "987654321", "456789123"]
    - Multiple properties as comma-separated string: property_id="123456789,987654321,456789123"
    
    When querying multiple properties:
    - Results include 'source_property_id' field for attribution
    - Data is aggregated from all specified properties
    - Partial failures are reported in 'property_results'
    
    Filtering Behavior:
    - When property_id is specified: No domain filtering applied (for maximum data reliability)
    - When property_id is omitted: domain_filter applies to all properties (for cross-property filtering)
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        property_id: Single property ID, list of property IDs, or comma-separated string (optional, queries all properties if not specified)
        domain_filter: Filter by hostname (optional, only applied when querying all properties)
        metrics: Comma-separated metrics (default: screenPageViews,totalAdRevenue,sessions)
        dimensions: Comma-separated dimensions (default: pagePath)
        debug: Enable debug output
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    logger.info(f"[{request_id}] Starting GA4 query - dates: {start_date} to {end_date}, property: {property_id or 'all'}, domain: {domain_filter or 'all'}")
    
    if not start_date or not end_date:
        error_msg = "start_date and end_date are required parameters"
        logger.warning(f"[{request_id}] GA4 query failed - {error_msg}")
        return add_today_date_to_response({"status": "error", "message": error_msg, "request_id": request_id})
    
    if not validate_date_range(start_date, end_date):
        error_msg = "Invalid date range"
        logger.warning(f"[{request_id}] GA4 query failed - {error_msg}: {start_date} to {end_date}")
        return add_today_date_to_response({"status": "error", "message": error_msg, "request_id": request_id})
    
    # Validate dimensions and metrics before API call
    validation_result = validate_ga4_dimensions_metrics(dimensions, metrics)
    if not validation_result["valid"]:
        error_msg = "Invalid dimensions or metrics detected"
        validation_details = {
            "status": "error", 
            "message": error_msg,
            "warnings": validation_result["warnings"],
            "suggestions": validation_result["suggestions"],
            "request_id": request_id,
            "todays_date": datetime.now().strftime('%Y-%m-%d')
        }
        logger.warning(f"[{request_id}] GA4 query failed - {error_msg}: {validation_result['warnings']}")
        return validation_details
    
    try:
        # Parse property_id input to handle multiple properties
        property_ids = parse_multi_input(property_id)
        
        if property_ids:
            # Multiple properties or single property specified
            if len(property_ids) == 1:
                logger.info(f"[{request_id}] Querying single GA4 property: {property_ids[0]}")
                # Single property - use existing logic for compatibility
                df = GA4query3.produce_report(
                    start_date=start_date,
                    end_date=end_date,
                    property_id=property_ids[0],
                    property_name="MCP_Property",
                    account=auth_identifier,
                    filter_expression=None,  # No domain filtering when property_id is specified
                    dimensions=dimensions,
                    metrics=metrics,
                    debug=debug
                )
                
                if df is not None and not df.empty:
                    # Add source attribution for consistency
                    df['source_property_id'] = property_ids[0]
                    df['source_type'] = 'ga4'
                    
                    duration = time.time() - start_time
                    logger.info(f"[{request_id}] GA4 query successful - {len(df)} rows retrieved in {duration:.2f}s")
                    return add_today_date_to_response({
                        "status": "success",
                        "message": f"Retrieved {len(df)} rows of GA4 data",
                        "date_range": {"start_date": start_date, "end_date": end_date},
                        "property_id": property_ids[0],
                        "data": df.to_dict('records'),
                        "row_count": len(df),
                        "source": "ga4",
                        "request_id": request_id,
                        "duration_seconds": round(duration, 2)
                    })
                else:
                    duration = time.time() - start_time
                    logger.info(f"[{request_id}] GA4 query completed - no data found in {duration:.2f}s")
                    return add_today_date_to_response({
                        "status": "success", 
                        "message": "No GA4 data found for the specified criteria", 
                        "data": [], 
                        "row_count": 0, 
                        "source": "ga4",
                        "request_id": request_id,
                        "duration_seconds": round(duration, 2)
                    })
            else:
                # Multiple properties - use new concurrent processing
                logger.info(f"[{request_id}] Querying {len(property_ids)} GA4 properties: {property_ids}")
                result = await process_multiple_properties_ga4(
                    property_ids=property_ids,
                    start_date=start_date,
                    end_date=end_date,
                    auth_identifier=auth_identifier,
                    dimensions=dimensions,
                    metrics=metrics,
                    debug=debug
                )
                
                duration = time.time() - start_time
                result.update({
                    "date_range": {"start_date": start_date, "end_date": end_date},
                    "property_ids": property_ids,
                    "source": "ga4",
                    "request_id": request_id,
                    "duration_seconds": round(duration, 2)
                })
                
                logger.info(f"[{request_id}] Multi-property GA4 query completed - {result['row_count']} total rows in {duration:.2f}s")
                return add_today_date_to_response(result)
        else:
            logger.info(f"[{request_id}] Querying all available GA4 properties")
            properties_df = GA4query3.list_properties(auth_identifier, debug=debug)
            if properties_df is None or properties_df.empty:
                error_msg = "No GA4 properties found"
                logger.warning(f"[{request_id}] GA4 query failed - {error_msg}")
                return {"status": "error", "message": error_msg, "request_id": request_id, "todays_date": datetime.now().strftime('%Y-%m-%d')}
            
            logger.info(f"[{request_id}] Found {len(properties_df)} GA4 properties to query")
            
            # Extract property IDs and use multi-property processing
            all_property_ids = []
            for idx, row in properties_df.iterrows():
                pid = row.get("property_id") or row.get("id")
                if pid:
                    all_property_ids.append(str(pid))
            
            if all_property_ids:
                # Use multi-property processing for all properties
                result = await process_multiple_properties_ga4(
                    property_ids=all_property_ids,
                    start_date=start_date,
                    end_date=end_date,
                    auth_identifier=auth_identifier,
                    dimensions=dimensions,
                    metrics=metrics,
                    debug=debug
                )
                
                # Apply domain filtering to combined results if specified
                if domain_filter and result.get("data"):
                    original_count = result["row_count"]
                    filtered_data = [row for row in result["data"] if row.get("hostname") == domain_filter]
                    result["data"] = filtered_data
                    result["row_count"] = len(filtered_data)
                    if debug:
                        logger.info(f"[{request_id}] Applied domain filter '{domain_filter}': {original_count} -> {len(filtered_data)} rows")
                
                duration = time.time() - start_time
                result.update({
                    "date_range": {"start_date": start_date, "end_date": end_date},
                    "domain_filter": domain_filter,
                    "source": "ga4",
                    "request_id": request_id,
                    "duration_seconds": round(duration, 2)
                })
                
                logger.info(f"[{request_id}] All-properties GA4 query completed - {result['row_count']} total rows in {duration:.2f}s")
                return add_today_date_to_response(result)
            else:
                error_msg = "No valid GA4 property IDs found"
                logger.warning(f"[{request_id}] GA4 query failed - {error_msg}")
                return add_today_date_to_response({"status": "error", "message": error_msg, "request_id": request_id})
    except Exception as e:
        duration = time.time() - start_time
        error_msg = f"GA4 query failed: {str(e)}"
        logger.error(f"GA4 query exception - {error_msg}, duration: {duration:.2f}s", exc_info=True)
        return {"status": "error", "message": error_msg, "request_id": request_id, "todays_date": datetime.now().strftime('%Y-%m-%d')}

@mcp.tool()
async def query_gsc_data(start_date: str, end_date: str, auth_identifier: str = "", domain: Union[str, List[str]] = "", dimensions: str = "page,query,country,device", search_type: str = "web", debug: bool = False) -> dict:
    """
    Query Google Search Console data for search performance analysis.
    
    Business Use Cases:
    - Identify high-impression, low-click pages needing content optimization
    - Find keyword opportunities with good ranking but poor CTR
    - Analyze page performance across different devices and countries
    - Discover content gaps where rankings could be improved
    
    Common Dimensions: page, query, country, device, date, searchAppearance
    Common Metrics: clicks, impressions, ctr, position (automatically included)
    
    Example: Find underperforming pages with good rankings:
    - dimensions: "page,query" to see page-keyword combinations
    - Filter results for position < 10 but ctr < 0.05 (5%)
    
    Example: Identify mobile vs desktop performance:
    - dimensions: "page,device" to compare device performance
    
    Multi-Domain Usage Examples:
    - Single domain: domain="example.com"
    - Multiple domains as list: domain=["example.com", "subdomain.example.com", "another-site.com"]
    - Multiple domains as comma-separated string: domain="example.com,subdomain.example.com,another-site.com"
    
    When querying multiple domains:
    - Results include 'source_domain' field for attribution
    - Data is aggregated from all specified domains
    - Partial failures are reported in 'domain_results'
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        domain: Single domain, list of domains, or comma-separated string (optional, queries all domains if not specified)
        dimensions: Comma-separated dimensions (default: page,query,country,device)
        search_type: Type of search data - web, image, video (default: web)
        debug: Enable debug output
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    # Parse domain input to handle multiple domains
    domains_list = parse_multi_input(domain)
    logger.info(f"Starting GSC query - dates: {start_date} to {end_date}, domain(s): {domains_list if domains_list else 'all'}, search_type: {search_type}")
    
    if not start_date or not end_date:
        error_msg = "start_date and end_date are required parameters"
        logger.warning(f"GSC query failed - {error_msg}")
        return {"status": "error", "message": error_msg, "request_id": request_id, "todays_date": datetime.now().strftime('%Y-%m-%d')}
    
    if not validate_date_range(start_date, end_date):
        error_msg = "Invalid date range"
        logger.warning(f"GSC query failed - {error_msg}: {start_date} to {end_date}")
        return {"status": "error", "message": error_msg, "request_id": request_id, "todays_date": datetime.now().strftime('%Y-%m-%d')}
    
    try:
        # Parse domain input to handle multiple domains
        domains = parse_multi_input(domain)
        
        if domains:
            # Multiple domains or single domain specified
            if len(domains) == 1:
                logger.info(f"[{request_id}] Querying single GSC domain: {domains[0]}")
                # Single domain - use existing logic for compatibility
                logger.info(f"[{request_id}] Calling fetch_search_console_data_async with params: start_date={start_date}, end_date={end_date}, search_type={search_type}, dimensions={dimensions}, google_account={auth_identifier}, wait_seconds=0, debug={debug}, domain_filter={domains[0]}")
                df = await NewDownloads.fetch_search_console_data_async(
                    start_date=start_date,
                    end_date=end_date,
                    search_type=search_type,
                    dimensions=dimensions,
                    google_account=auth_identifier,
                    wait_seconds=0,
                    debug=debug,
                    domain_filter=domains[0]
                )
                
                if df is not None and not df.empty:
                    # Add source attribution for consistency
                    df['source_domain'] = domains[0]
                    df['source_type'] = 'gsc'
                    
                    duration = time.time() - start_time
                    logger.info(f"[{request_id}] GSC query successful - {len(df)} rows retrieved in {duration:.2f}s")
                    return {
                        "status": "success",
                        "message": f"Retrieved {len(df)} rows of GSC data",
                        "date_range": {"start_date": start_date, "end_date": end_date},
                        "domain": domains[0],
                        "data": df.to_dict('records'),
                        "row_count": len(df),
                        "source": "gsc",
                        "request_id": request_id,
                        "duration_seconds": round(duration, 2),
                        "todays_date": datetime.now().strftime('%Y-%m-%d')
                    }
                else:
                    duration = time.time() - start_time
                    logger.info(f"[{request_id}] GSC query completed - no data found in {duration:.2f}s")
                    return {
                        "status": "success", 
                        "message": "No GSC data found for the specified criteria", 
                        "data": [], 
                        "row_count": 0, 
                        "source": "gsc",
                        "request_id": request_id,
                        "duration_seconds": round(duration, 2),
                        "todays_date": datetime.now().strftime('%Y-%m-%d')
                    }
            else:
                # Multiple domains - use new concurrent processing
                logger.info(f"[{request_id}] Querying {len(domains)} GSC domains: {domains}")
                result = await process_multiple_domains_gsc(
                    domains=domains,
                    start_date=start_date,
                    end_date=end_date,
                    auth_identifier=auth_identifier,
                    dimensions=dimensions,
                    search_type=search_type,
                    debug=debug
                )
                
                duration = time.time() - start_time
                result.update({
                    "date_range": {"start_date": start_date, "end_date": end_date},
                    "domains": domains,
                    "source": "gsc",
                    "request_id": request_id,
                    "duration_seconds": round(duration, 2),
                    "todays_date": datetime.now().strftime('%Y-%m-%d')
                })
                
                logger.info(f"[{request_id}] Multi-domain GSC query completed - {result['row_count']} total rows in {duration:.2f}s")
                return result
        else:
            logger.info(f"[{request_id}] Querying all available GSC domains")
            # Query all domains - use the existing logic but through our new processing
            logger.info(f"[{request_id}] Calling fetch_search_console_data_async with params: start_date={start_date}, end_date={end_date}, search_type={search_type}, dimensions={dimensions}, google_account={auth_identifier}, wait_seconds=0, debug={debug}, domain_filter=None (all domains)")
            df = await NewDownloads.fetch_search_console_data_async(
                start_date=start_date,
                end_date=end_date,
                search_type=search_type,
                dimensions=dimensions,
                google_account=auth_identifier,
                wait_seconds=0,
                debug=debug,
                domain_filter=None  # Query all domains
            )
            
            if df is not None and not df.empty:
                # Add source attribution
                df['source_type'] = 'gsc'
                # Note: When querying all domains, the source_domain will be derived from the data itself
                
                duration = time.time() - start_time
                logger.info(f"[{request_id}] All-domains GSC query successful - {len(df)} rows retrieved in {duration:.2f}s")
                return {
                    "status": "success",
                    "message": f"Retrieved {len(df)} rows of GSC data from all domains",
                    "date_range": {"start_date": start_date, "end_date": end_date},
                    "data": df.to_dict('records'),
                    "row_count": len(df),
                    "source": "gsc",
                    "request_id": request_id,
                    "duration_seconds": round(duration, 2),
                    "todays_date": datetime.now().strftime('%Y-%m-%d')
                }
            else:
                duration = time.time() - start_time
                logger.info(f"[{request_id}] All-domains GSC query completed - no data found in {duration:.2f}s")
                return {
                    "status": "success", 
                    "message": "No GSC data found for the specified criteria", 
                    "data": [], 
                    "row_count": 0, 
                    "source": "gsc",
                    "request_id": request_id,
                    "duration_seconds": round(duration, 2),
                    "todays_date": datetime.now().strftime('%Y-%m-%d')
                }
    except Exception as e:
        duration = time.time() - start_time
        error_msg = f"GSC query failed: {str(e)}"
        logger.error(f"GSC query exception - {error_msg}, duration: {duration:.2f}s", exc_info=True)
        return {"status": "error", "message": error_msg, "request_id": request_id, "todays_date": datetime.now().strftime('%Y-%m-%d')}

# @mcp.tool()
# async def query_unified_data(start_date: str, end_date: str, auth_identifier: str = "", domain: str = "", ga4_property_id: str = "", data_sources: list = ["ga4", "gsc"], debug: bool = False) -> dict:
#     """
#     Query both GA4 and GSC data for comprehensive cross-platform analysis.
   
#     Business Use Cases:
#     - Compare organic search performance (GSC) with actual user behavior (GA4)
#     - Identify pages with high search impressions but low GA4 pageviews (optimization opportunity)
#     - Cross-reference revenue data with search performance
#     - Comprehensive SEO and monetization analysis
   
#     This tool combines data from both platforms to provide insights that neither platform 
#     alone can offer, ideal for holistic website performance analysis.
   
#     Args:
#         start_date: Start date in YYYY-MM-DD format (required)
#         end_date: End date in YYYY-MM-DD format (required)
#         domain: Domain to analyze (optional, analyzes all domains if not specified)
#         ga4_property_id: Specific GA4 property ID (optional)
#         data_sources: List of data sources to query - ["ga4"], ["gsc"], or ["ga4", "gsc"] (default: both)
#         debug: Enable debug output
#     """
#     if not start_date or not end_date:
#         return {"status": "error", "message": "start_date and end_date are required parameters", "todays_date": datetime.now().strftime('%Y-%m-%d')}
#     if not validate_date_range(start_date, end_date):
#         return {"status": "error", "message": "Invalid date range", "todays_date": datetime.now().strftime('%Y-%m-%d')}
#     results = []
#     errors = []
#     if "ga4" in data_sources:
#         ga4_result = await query_ga4_data(auth_identifier, start_date, end_date, ga4_property_id, domain, debug=debug)
#         if ga4_result.get("status") == "success":
#             results.append(ga4_result)
#         else:
#             errors.append(ga4_result.get("message"))
#     if "gsc" in data_sources:
#         gsc_result = await query_gsc_data(auth_identifier, start_date, end_date, domain, debug=debug)
#         if gsc_result.get("status") == "success":
#             results.append(gsc_result)
#         else:
#             errors.append(gsc_result.get("message"))
#     if not results and errors:
#         return {"status": "error", "message": "; ".join(errors), "todays_date": datetime.now().strftime('%Y-%m-%d')}
#     if errors:
#         return {"status": "partial_success", "message": f"Retrieved data from {len(results)} source(s) with {len(errors)} error(s)", "errors": errors, "results": results, "todays_date": datetime.now().strftime('%Y-%m-%d')}
#     return {"status": "success", "message": f"Retrieved data from {len(results)} source(s)", "results": results, "todays_date": datetime.now().strftime('%Y-%m-%d')}

@mcp.tool()
async def validate_ga4_parameters(dimensions: str = "", metrics: str = "") -> dict:
    """
    Validate GA4 dimensions and metrics before making API calls to avoid errors.
    
    Use this tool to check if your dimensions and metrics are valid before querying data.
    This helps prevent 400 errors and provides helpful suggestions for corrections.
    
    Args:
        dimensions: Comma-separated dimensions to validate (optional)
        metrics: Comma-separated metrics to validate (optional)
        
    Returns:
        dict: Validation results with warnings and suggestions
    """
    request_id = str(uuid.uuid4())[:8]
    
    if not dimensions and not metrics:
        return {
            "status": "error",
            "message": "Please provide dimensions or metrics to validate",
            "request_id": request_id,
            "todays_date": datetime.now().strftime('%Y-%m-%d')
        }
    
    validation_result = validate_ga4_dimensions_metrics(dimensions, metrics)
    
    response = {
        "status": "success" if validation_result["valid"] else "warning",
        "message": "Parameters validated",
        "valid": validation_result["valid"],
        "request_id": request_id,
        "todays_date": datetime.now().strftime('%Y-%m-%d')
    }
    
    if validation_result["warnings"]:
        response["warnings"] = validation_result["warnings"]
    
    if validation_result["suggestions"]:
        response["suggestions"] = validation_result["suggestions"]
    
    if validation_result["valid"]:
        response["message"] = "All dimensions and metrics appear valid"
    else:
        response["message"] = "Issues found with dimensions or metrics"
    
    return response

@mcp.tool()
async def list_ga4_properties(auth_identifier: str = "", debug: bool = False) -> dict:
    """
    List all available GA4 properties for the authenticated account.
    
    Use this tool to discover which GA4 properties you have access to before running
    detailed analytics queries. Essential for multi-property setups or when you need
    to identify the correct property_id for focused analysis.
    
    Args:
        debug: Enable debug output
    """
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    try:
        logger.info(f"[{request_id}] Listing GA4 properties")
        properties_df = GA4query3.list_properties(auth_identifier, debug=debug)
        if properties_df is not None and not properties_df.empty:
            logger.info(f"[{request_id}] Found {len(properties_df)} GA4 properties")
            return {
                "status": "success",
                "message": f"Found {len(properties_df)} GA4 properties",
                "properties": properties_df.to_dict('records'),
                "request_id": request_id,
                "todays_date": datetime.now().strftime('%Y-%m-%d')
            }
        else:
            logger.info(f"[{request_id}] No GA4 properties found")
            return {
                "status": "success", 
                "message": "No GA4 properties found", 
                "properties": [],
                "request_id": request_id,
                "todays_date": datetime.now().strftime('%Y-%m-%d')
            }
    except Exception as e:
        error_msg = f"Failed to list GA4 properties: {str(e)}"
        logger.error(f"[{request_id}] {error_msg}", exc_info=True)
        return {
            "status": "error", 
            "message": error_msg,
            "request_id": request_id,
            "todays_date": datetime.now().strftime('%Y-%m-%d')
        }

@mcp.tool()
async def list_gsc_domains(auth_identifier: str = "", debug: bool = False) -> dict:
    """
    List all available Google Search Console domains for the authenticated account.
    
    Use this tool to discover which domains/sites you have access to before running
    search performance queries. Essential for multi-domain setups or when you need
    to identify the correct domain parameter for focused analysis.
    
    Args:
        debug: Enable debug output
    """
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    try:
        logger.info(f"[{request_id}] Listing GSC domains")
        domains_df = NewDownloads.list_search_console_sites(google_account=auth_identifier, debug=debug)
        if domains_df is not None and not domains_df.empty:
            logger.info(f"[{request_id}] Found {len(domains_df)} GSC domains")
            return {
                "status": "success",
                "message": f"Found {len(domains_df)} GSC domains",
                "domains": domains_df.to_dict('records'),
                "request_id": request_id,
                "todays_date": datetime.now().strftime('%Y-%m-%d')
            }
        else:
            logger.info(f"[{request_id}] No GSC domains found")
            return {
                "status": "success", 
                "message": "No GSC domains found", 
                "domains": [],
                "request_id": request_id,
                "todays_date": datetime.now().strftime('%Y-%m-%d')
            }
    except Exception as e:
        error_msg = f"Failed to list GSC domains: {str(e)}"
        logger.error(f"[{request_id}] {error_msg}", exc_info=True)
        return {
            "status": "error", 
            "message": error_msg,
            "request_id": request_id,
            "todays_date": datetime.now().strftime('%Y-%m-%d')
        }

# Focused GA4 Business-Intent Tools

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache page performance queries for 1 hour
async def page_performance_ga4(start_date: str, end_date: str, auth_identifier: str = "", property_id: Union[str, List[str]] = "", domain_filter: str = "", debug: bool = False) -> dict:
    """
    Analyze page performance metrics for content optimization and SEO.
    
    Business Purpose: Identify your best and worst performing pages to optimize content strategy.
    Perfect for finding pages that need attention or content that's working well.
    
    This tool focuses on:
    - Which pages get the most visits and engagement
    - Time spent on each page (engagement quality)
    - Bounce rates and user retention
    - Page performance across different devices
    
    Returns data optimized for: Content optimization, SEO strategy, user experience improvements
    
    Multi-Property Usage Examples:
    - Single property: property_id="123456789"
    - Multiple properties as list: property_id=["123456789", "987654321"]
    - Multiple properties as comma-separated: property_id="123456789,987654321"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        property_id: Single property ID, list of property IDs, or comma-separated string (optional)
        domain_filter: Filter by hostname (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions and metrics optimized for page performance analysis
    dimensions = "pagePath,deviceCategory"
    metrics = "screenPageViews,sessions,userEngagementDuration,bounceRate,totalUsers"
    
    return await query_ga4_data(start_date, end_date, auth_identifier, property_id, domain_filter, metrics, dimensions, debug)

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache traffic sources queries for 1 hour
async def traffic_sources_ga4(start_date: str, end_date: str, auth_identifier: str = "", property_id: Union[str, List[str]] = "", domain_filter: str = "", debug: bool = False) -> dict:
    """
    Analyze traffic sources to understand how visitors find your website.
    
    Business Purpose: Optimize marketing spend and SEO efforts by understanding which 
    channels drive the most valuable traffic. Essential for marketing ROI analysis.
    
    This tool focuses on:
    - Which sources drive the most traffic (organic, social, direct, referral)
    - Medium and campaign performance analysis  
    - Geographic distribution of traffic sources
    - Source quality based on engagement metrics
    
    Returns data optimized for: Marketing optimization, channel attribution, campaign analysis
    
    Multi-Property Usage Examples:
    - Single property: property_id="123456789"
    - Multiple properties as list: property_id=["123456789", "987654321"]
    - Multiple properties as comma-separated: property_id="123456789,987654321"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        property_id: Single property ID, list of property IDs, or comma-separated string (optional)
        domain_filter: Filter by hostname (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions and metrics optimized for traffic source analysis
    dimensions = "sessionSource,sessionMedium,country"
    metrics = "sessions,totalUsers,userEngagementDuration,bounceRate,screenPageViews"
    
    return await query_ga4_data(start_date, end_date, auth_identifier, property_id, domain_filter, metrics, dimensions, debug)

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache audience analysis queries for 1 hour
async def audience_analysis_ga4(start_date: str, end_date: str, auth_identifier: str = "", property_id: Union[str, List[str]] = "", domain_filter: str = "", debug: bool = False) -> dict:
    """
    Analyze your website audience demographics and behavior patterns.
    
    Business Purpose: Understand your audience to create better content and optimize 
    user experience. Essential for content strategy and personalization efforts.
    
    This tool focuses on:
    - Geographic distribution of your audience
    - Device and technology preferences  
    - Language and browser patterns
    - Operating system and screen resolution data
    
    Returns data optimized for: Content personalization, UX optimization, market research
    
    Multi-Property Usage Examples:
    - Single property: property_id="123456789"
    - Multiple properties as list: property_id=["123456789", "987654321"]
    - Multiple properties as comma-separated: property_id="123456789,987654321"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        property_id: Single property ID, list of property IDs, or comma-separated string (optional)
        domain_filter: Filter by hostname (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions and metrics optimized for audience analysis
    dimensions = "country,deviceCategory,operatingSystem,browser,language"
    metrics = "totalUsers,sessions,userEngagementDuration,screenPageViews"
    
    return await query_ga4_data(start_date, end_date, auth_identifier, property_id, domain_filter, metrics, dimensions, debug)

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache revenue analysis queries for 1 hour
async def revenue_analysis_ga4(start_date: str, end_date: str, auth_identifier: str = "", property_id: Union[str, List[str]] = "", domain_filter: str = "", debug: bool = False) -> dict:
    """
    Analyze AdSense revenue and monetization performance across your website.
    
    Business Purpose: Maximize ad revenue by understanding which pages, traffic sources,
    and audience segments generate the most income. Critical for monetization optimization.
    
    This tool focuses on:
    - Revenue by page (which content makes money)
    - Revenue by traffic source (which channels are most profitable)
    - Revenue by geography and device type
    - Revenue trends and patterns
    
    Returns data optimized for: Monetization strategy, ad placement optimization, revenue growth
    
    Multi-Property Usage Examples:
    - Single property: property_id="123456789"
    - Multiple properties as list: property_id=["123456789", "987654321"]
    - Multiple properties as comma-separated: property_id="123456789,987654321"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        property_id: Single property ID, list of property IDs, or comma-separated string (optional)
        domain_filter: Filter by hostname (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions and metrics optimized for revenue analysis
    dimensions = "pagePath,sessionSource,country,deviceCategory"
    metrics = "totalAdRevenue,publisherAdClicks,publisherAdImpressions,screenPageViews,sessions,totalUsers"
    
    return await query_ga4_data(start_date, end_date, auth_identifier, property_id, domain_filter, metrics, dimensions, debug)

# Focused GSC Business-Intent Tools

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache GSC page performance queries for 1 hour
async def page_performance_gsc(start_date: str, end_date: str, auth_identifier: str = "", domain: Union[str, List[str]] = "", debug: bool = False) -> dict:
    """
    Analyze page performance in Google Search to identify SEO optimization opportunities.
    
    Business Purpose: Find pages with high potential that need optimization - either pages 
    getting impressions but poor clicks, or pages with good rankings but room for improvement.
    
    This tool focuses on:
    - Pages with high impressions but low click-through rates (CTR optimization needed)
    - Pages with good rankings but poor CTR (title/meta description optimization)
    - Page performance across different devices and countries
    - Position trends for your most important pages
    
    Returns data optimized for: Content optimization, title/meta improvements, CTR optimization
    
    Multi-Domain Usage Examples:
    - Single domain: domain="example.com"
    - Multiple domains as list: domain=["example.com", "subdomain.example.com"]
    - Multiple domains as comma-separated: domain="example.com,subdomain.example.com"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        domain: Single domain, list of domains, or comma-separated string (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions optimized for page performance analysis
    dimensions = "page,country,device"
    
    return await query_gsc_data(start_date, end_date, auth_identifier, domain, dimensions, "web", debug)

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache GSC query analysis for 1 hour
async def query_analysis_gsc(start_date: str, end_date: str, auth_identifier: str = "", domain: Union[str, List[str]] = "", debug: bool = False) -> dict:
    """
    Analyze search query performance to identify keyword opportunities and content gaps.
    
    Business Purpose: Discover which keywords you rank for and find opportunities to improve
    rankings or target new keywords. Essential for SEO content strategy.
    
    This tool focuses on:
    - Keywords with high impressions but low rankings (content improvement opportunities)
    - Keywords where you rank well but have poor CTR (meta optimization needed)
    - Emerging keyword trends and seasonal patterns
    - Geographic and device-specific keyword performance
    
    Returns data optimized for: Keyword strategy, content planning, SEO optimization
    
    Multi-Domain Usage Examples:
    - Single domain: domain="example.com"
    - Multiple domains as list: domain=["example.com", "subdomain.example.com"]
    - Multiple domains as comma-separated: domain="example.com,subdomain.example.com"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        domain: Single domain, list of domains, or comma-separated string (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions optimized for query analysis
    dimensions = "query,country,device"
    
    return await query_gsc_data(start_date, end_date, auth_identifier, domain, dimensions, "web", debug)

@mcp.tool()
@async_persistent_cache(expire_time=3600)  # Cache GSC page-query opportunities for 1 hour
async def page_query_opportunities_gsc(start_date: str, end_date: str, auth_identifier: str = "", domain: Union[str, List[str]] = "", debug: bool = False) -> dict:
    """
    Analyze page-query combinations to find content optimization opportunities.
    
    Business Purpose: Identify specific page-keyword combinations where you can improve
    rankings through content optimization. Perfect for finding quick SEO wins.
    
    This tool focuses on:
    - Page-keyword pairs with good impressions but poor rankings
    - Content that ranks on page 2-3 of Google (positions 11-30) with optimization potential
    - Pages that could rank for additional related keywords
    - Content gaps where competitors outrank you
    
    Returns data optimized for: Content optimization, on-page SEO, competitive analysis
    
    Multi-Domain Usage Examples:
    - Single domain: domain="example.com"
    - Multiple domains as list: domain=["example.com", "subdomain.example.com"]
    - Multiple domains as comma-separated: domain="example.com,subdomain.example.com"
    
    Args:
        start_date: Start date in YYYY-MM-DD format (required)
        end_date: End date in YYYY-MM-DD format (required)
        domain: Single domain, list of domains, or comma-separated string (optional)
        debug: Enable debug output
    """
    if not start_date or not end_date:
        return {"status": "error", "message": "start_date and end_date are required parameters"}
    
    # Use specific dimensions optimized for page-query opportunity analysis
    dimensions = "page,query"
    
    return await query_gsc_data(start_date, end_date, auth_identifier, domain, dimensions, "web", debug)

@mcp.tool()
async def get_server_stats(include_details: bool = False) -> dict:
    """
    Get MCP server statistics and health information for monitoring and debugging.
    
    Business Purpose: Monitor server performance, authentication patterns, and usage analytics
    to ensure optimal operation and identify potential issues or security concerns.
    
    This tool provides:
    - Request volume and success/failure rates
    - Authentication method usage and failure patterns
    - Performance metrics (average response times)
    - Rate limiting statistics
    - Active session information
    - Domain cache performance (NEW - for timeout optimization)
    
    Returns data optimized for: Server monitoring, performance analysis, security auditing
    
    Args:
        include_details: Include detailed breakdown of statistics (default: False)
    """
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    logger.info("Retrieving server statistics")
    
    try:
        # Get basic stats
        basic_stats = {
            'server_uptime_seconds': time.time() - start_time,
            'current_time': datetime.now().isoformat(),
            'request_id': request_id,
            'todays_date': datetime.now().strftime('%Y-%m-%d')
        }
        
        # Get request tracker stats
        tracker_stats = request_tracker.get_stats()
        
        # Get domain cache stats for performance monitoring
        domain_cache_stats = NewDownloads.get_domain_cache_stats()
        
        # Get disk cache stats for comprehensive monitoring  
        disk_cache_stats = NewDownloads.get_disk_cache_stats()
        
        # Get comprehensive cache health validation
        cache_health = NewDownloads.validate_cache_health()
        
        # Get basic auth stats (since middleware might not be available in stdio mode)
        auth_stats = {
            'auth_stats': {},
            'unique_ips': 0,
            'rate_limited': 0
        }
        
        stats = {
            'status': 'success',
            'message': 'Server statistics retrieved successfully',
            'basic_info': basic_stats,
            'request_metrics': tracker_stats,
            'domain_cache_metrics': domain_cache_stats,  # Memory-based domain cache
            'disk_cache_metrics': disk_cache_stats,      # Persistent disk cache
            'cache_health': cache_health,                # Comprehensive cache health
            'authentication_metrics': auth_stats.get('auth_stats', {}),
            'rate_limiting': {
                'unique_ips': auth_stats.get('unique_ips', 0),
                'rate_limited_requests': auth_stats.get('rate_limited', 0)
            }
        }
        
        if include_details:
            stats['detailed_metrics'] = {
                'success_rate': (tracker_stats.get('successful_requests', 0) / 
                               max(tracker_stats.get('total_requests', 1), 1)) * 100,
                'failure_rate': (tracker_stats.get('failed_requests', 0) / 
                               max(tracker_stats.get('total_requests', 1), 1)) * 100,
                'auth_failure_rate': (tracker_stats.get('auth_failures', 0) / 
                                     max(tracker_stats.get('total_requests', 1), 1)) * 100,
                'avg_response_time_ms': tracker_stats.get('avg_response_time', 0) * 1000,
                'cache_hit_rate': (domain_cache_stats.get('stats', {}).get('hits', 0) / 
                                 max(domain_cache_stats.get('stats', {}).get('hits', 0) + 
                                     domain_cache_stats.get('stats', {}).get('misses', 0), 1)) * 100,
                'overall_cache_healthy': cache_health.get('overall_healthy', False)
            }
        
        logger.info(f"Server stats retrieved - {tracker_stats.get('total_requests', 0)} total requests processed")
        return stats
        
    except Exception as e:
        error_msg = f"Failed to retrieve server statistics: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'status': 'error',
            'message': error_msg,
            'request_id': request_id,
            'todays_date': datetime.now().strftime('%Y-%m-%d')
        }


@mcp.tool()
async def invalidate_cache(cache_type: str = "domain", account: str = "") -> dict:
    """
    Invalidate server caches to force fresh data retrieval.
    
    Business Purpose: Allow manual cache invalidation when fresh data is needed
    or when troubleshooting performance issues.
    
    Args:
        cache_type: Type of cache to invalidate ('domain', 'disk', or 'all')
        account: Specific account to invalidate (empty = all accounts)
        
    Returns:
        dict: Operation status and cache statistics
    """
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    try:
        if cache_type.lower() == "domain":
            # Get stats before invalidation
            stats_before = NewDownloads.get_domain_cache_stats()
            
            # Invalidate cache
            NewDownloads.invalidate_domain_cache(account if account else None)
            
            # Get stats after invalidation
            stats_after = NewDownloads.get_domain_cache_stats()
            
            logger.info(f"Domain cache invalidated - account: {account or 'all'}")
            
            return {
                'status': 'success',
                'message': f"Domain cache invalidated for {account or 'all accounts'}",
                'cache_stats_before': stats_before,
                'cache_stats_after': stats_after,
                'request_id': request_id,
                'todays_date': datetime.now().strftime('%Y-%m-%d')
            }
        elif cache_type.lower() == "disk":
            # Get stats before invalidation
            stats_before = NewDownloads.get_disk_cache_stats()
            
            # Clear disk cache
            NewDownloads.clear_disk_cache()
            
            # Get stats after invalidation  
            stats_after = NewDownloads.get_disk_cache_stats()
            
            logger.info(f"Disk cache cleared")
            
            return {
                'status': 'success',
                'message': 'Disk cache cleared',
                'cache_stats_before': stats_before,
                'cache_stats_after': stats_after,
                'request_id': request_id,
                'todays_date': datetime.now().strftime('%Y-%m-%d')
            }
        elif cache_type.lower() == "all":
            # Get stats before invalidation
            domain_stats_before = NewDownloads.get_domain_cache_stats()
            disk_stats_before = NewDownloads.get_disk_cache_stats()
            
            # Invalidate all caches
            NewDownloads.invalidate_domain_cache(account if account else None)
            NewDownloads.clear_disk_cache()
            
            # Get stats after invalidation
            domain_stats_after = NewDownloads.get_domain_cache_stats()
            disk_stats_after = NewDownloads.get_disk_cache_stats()
            
            logger.info(f"All caches invalidated - account: {account or 'all'}")
            
            return {
                'status': 'success',
                'message': f"All caches invalidated for {account or 'all accounts'}",
                'domain_cache_before': domain_stats_before,
                'domain_cache_after': domain_stats_after,
                'disk_cache_before': disk_stats_before,
                'disk_cache_after': disk_stats_after,
                'request_id': request_id,
                'todays_date': datetime.now().strftime('%Y-%m-%d')
            }
        else:
            return {
                'status': 'error',
                'message': f"Unknown cache type: {cache_type}. Supported types: 'domain', 'disk', 'all'",
                'request_id': request_id,
                'todays_date': datetime.now().strftime('%Y-%m-%d')
            }
            
    except Exception as e:
        error_msg = f"Failed to invalidate cache: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'status': 'error',
            'message': error_msg,
            'request_id': request_id,
            'todays_date': datetime.now().strftime('%Y-%m-%d')
        }

@mcp.tool()
async def debug_request_headers() -> dict:
    """
    Debug tool to show what headers and authentication the server is receiving.
    
    This tool helps diagnose authentication issues, especially when using proxies,
    tunnels, or load balancers that might modify headers.
    
    Returns:
        dict: Current request information and authentication details
    """
    request_id = str(uuid.uuid4())[:8]
    set_request_context(request_id)
    
    try:
        # Get the middleware stats to see auth patterns
        middleware_stats = middleware.get_stats() if middleware else {}
        
        return {
            'status': 'success',
            'message': 'Debug information retrieved',
            'server_info': {
                'request_id': request_id,
                'server_uptime_seconds': time.time() - start_time,
                'todays_date': datetime.now().strftime('%Y-%m-%d'),
                'current_time': datetime.now().isoformat()
            },
            'authentication_stats': middleware_stats,
            'debug_note': 'Check server logs for detailed header information on recent requests',
            'troubleshooting_tips': [
                'Compare local vs remote request logs to identify header differences',
                'Check if Cloudflare or proxy is stripping Authorization headers',
                'Verify VS Code MCP client is sending identical headers in both cases',
                'Consider using URL parameter authentication as fallback if headers are being modified'
            ]
        }
        
    except Exception as e:
        error_msg = f"Failed to get debug information: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'status': 'error',
            'message': error_msg,
            'request_id': request_id,
            'todays_date': datetime.now().strftime('%Y-%m-%d')
        }

# Simple Mode Resources and Prompts

@mcp.resource("ga4://dimensions-metrics-reference")
async def ga4_dimensions_metrics_reference() -> str:
    """
    Essential GA4 dimensions and metrics reference for business analytics.
    
    This resource provides a curated list of the most commonly used GA4 dimensions
    and metrics that deliver actionable business insights.
    """
    return """
# Google Analytics 4 (GA4) - Essential Dimensions & Metrics Reference

## Most Important Dimensions for Business Analytics

### Page/Content Analysis
- **pagePath** - The path portion of the page URL (e.g., '/about', '/products/shoes')
- **pageTitle** - The title of the page as it appears in the browser tab
- **hostname** - The hostname of the website (useful for multi-domain tracking)
- **landingPage** - The first page a user visits in their session

### Traffic Source Analysis  
- **sessionSource** - Where the traffic came from (google, facebook, direct, etc.)
- **sessionMedium** - The marketing medium (organic, cpc, email, referral, etc.)
- **sessionCampaign** - The marketing campaign name (for paid campaigns)

### User Demographics & Technology
- **country** - The user's country
- **city** - The user's city
- **deviceCategory** - Desktop, mobile, or tablet
- **browser** - Chrome, Safari, Firefox, etc.
- **operatingSystem** - Windows, macOS, Android, iOS, etc.

### Time-based Analysis
- **date** - YYYY-MM-DD format for daily analysis
- **dayOfWeek** - Monday, Tuesday, etc.
- **month** - January, February, etc.

## Most Important Metrics for Business Analytics

### Traffic & Engagement
- **screenPageViews** - Number of times a page was viewed
- **sessions** - Number of distinct sessions on your site
- **totalUsers** - Total number of unique users 
- **activeUsers** - Number of distinct users who visited your site
- **userEngagementDuration** - Total time users spent engaged with your site
- **averageSessionDuration** - Average length of a session
- **bounceRate** - Percentage of single-page sessions
- **engagementRate** - Percentage of engaged sessions

### Revenue & Monetization
- **totalAdRevenue** - Total ad revenue (for AdSense publishers)
- **publisherAdClicks** - Number of ad clicks
- **publisherAdImpressions** - Number of ad impressions
- **totalRevenue** - Total revenue from all sources

### Events & Conversions
- **eventCount** - Total number of events triggered
- **keyEvents** - Number of key events (conversions)

## Common Business Use Cases

### 1. Content Performance Analysis
- Dimensions: pagePath, deviceCategory
- Metrics: screenPageViews, sessions, userEngagementDuration, bounceRate

### 2. Traffic Source Analysis  
- Dimensions: sessionSource, sessionMedium, country
- Metrics: sessions, totalUsers, engagementRate, screenPageViews

### 3. Revenue Optimization
- Dimensions: pagePath, sessionSource, deviceCategory
- Metrics: totalAdRevenue, publisherAdClicks, screenPageViews, sessions

### 4. Audience Analysis
- Dimensions: country, deviceCategory, browser, operatingSystem
- Metrics: totalUsers, sessions, averageSessionDuration, engagementRate

## Important Notes
- Always pair dimensions with relevant metrics
- Use date dimension for time-series analysis
- Combine traffic source dimensions for attribution analysis
- Revenue metrics require proper AdSense/ecommerce setup
"""

@mcp.resource("gsc://dimensions-metrics-reference")
async def gsc_dimensions_metrics_reference() -> str:
    """
    Essential Google Search Console dimensions and metrics reference for SEO analytics.
    
    This resource provides a curated list of the most commonly used GSC dimensions
    and metrics that deliver actionable SEO insights.
    """
    return """
# Google Search Console (GSC) - Essential Dimensions & Metrics Reference

## Most Important Dimensions for SEO Analytics

### Page Analysis
- **page** - The URL of the page in search results (e.g., 'https://example.com/page')
- **query** - The search query that showed your page (keywords users searched for)

### Performance Segmentation
- **country** - Country where the search originated (US, GB, CA, etc.)
- **device** - Device type (desktop, mobile, tablet)
- **searchAppearance** - How your page appeared in search (web result, image, video, etc.)

### Time-based Analysis
- **date** - YYYY-MM-DD format for daily SEO tracking

## Metrics (Automatically Included)

All GSC queries automatically include these essential metrics:

### Search Performance Metrics
- **clicks** - Number of times users clicked on your page from search results
- **impressions** - Number of times your page appeared in search results  
- **ctr** - Click-through rate (clicks ÷ impressions × 100)
- **position** - Average ranking position in search results (1 = top position)

## Common SEO Use Cases

### 1. Page Performance Analysis
- Dimensions: page, country, device
- Focus on: pages with high impressions but low CTR, or good positions but low clicks

### 2. Keyword Opportunity Discovery  
- Dimensions: query, country, device
- Focus on: queries with high impressions but poor positions (optimization opportunities)

### 3. Content Optimization Opportunities
- Dimensions: page, query
- Focus on: page-query combinations with positions 11-30 (page 2-3 of Google)

### 4. Mobile vs Desktop Performance
- Dimensions: page, device
- Focus on: performance differences between mobile and desktop

### 5. Geographic Performance Analysis
- Dimensions: page, country or query, country
- Focus on: content performance in different markets

## Key Performance Indicators (KPIs)

### High-Priority Optimization Targets
- **High impressions + Low CTR**: Need better titles/meta descriptions
- **Positions 11-30**: Content improvement opportunities (page 2-3 of Google)
- **High impressions + Position > 10**: Potential for significant traffic gains
- **Low CTR on brand queries**: Potential SERP feature interference

### Success Metrics
- **CTR > 5%**: Generally good performance
- **Position < 10**: First page of Google
- **Position < 3**: Premium search visibility

## Important Notes
- Position is averaged across all impressions for the time period
- CTR varies significantly by position and industry
- Mobile and desktop performance can differ substantially
- Focus on impressions > 100 for reliable insights
- Use date dimension to track trends over time
"""

@mcp.resource("business://common-query-patterns")
async def common_query_patterns() -> str:
    """
    Common business analytics query patterns for GA4 and GSC data.
    
    This resource provides proven query structures that deliver actionable
    business insights for content optimization, SEO, and revenue analysis.
    """
    return """
# Common Business Analytics Query Patterns

## GA4 Query Patterns

### 1. Content Performance Analysis
**Purpose**: Identify your best and worst performing content
**Time Period**: Last 30 days
```
Dimensions: pagePath, deviceCategory
Metrics: screenPageViews, sessions, userEngagementDuration, bounceRate
Sort by: screenPageViews (descending)
```

### 2. Traffic Source ROI Analysis  
**Purpose**: Understand which channels drive the most valuable traffic
**Time Period**: Last 7-30 days
```
Dimensions: sessionSource, sessionMedium, country
Metrics: sessions, totalUsers, userEngagementDuration, bounceRate
Sort by: sessions (descending)
```

### 3. Revenue Optimization
**Purpose**: Maximize ad revenue by understanding top-earning pages
**Time Period**: Last 30 days
```
Dimensions: pagePath, sessionSource, deviceCategory
Metrics: totalAdRevenue, publisherAdClicks, screenPageViews, sessions
Sort by: totalAdRevenue (descending)
```

### 4. Audience Demographics
**Purpose**: Understand your audience for content personalization
**Time Period**: Last 30 days
```
Dimensions: country, deviceCategory, browser, operatingSystem
Metrics: totalUsers, sessions, averageSessionDuration, engagementRate
Sort by: totalUsers (descending)
```

## GSC Query Patterns

### 1. SEO Opportunity Discovery
**Purpose**: Find pages with high potential that need optimization
**Time Period**: Last 30 days
```
Dimensions: page, country, device
Metrics: clicks, impressions, ctr, position (automatic)
Focus on: impressions > 100 AND position > 10
```

### 2. Keyword Performance Analysis
**Purpose**: Discover keyword opportunities and content gaps
**Time Period**: Last 30 days
```
Dimensions: query, country, device
Metrics: clicks, impressions, ctr, position (automatic)
Focus on: impressions > 50 AND position > 10
```

### 3. Content Optimization Opportunities
**Purpose**: Find specific page-keyword combinations to optimize
**Time Period**: Last 30 days
```
Dimensions: page, query
Metrics: clicks, impressions, ctr, position (automatic)
Focus on: position between 11-30 (page 2-3 of Google)
```

### 4. Mobile vs Desktop Performance
**Purpose**: Optimize for different device experiences
**Time Period**: Last 30 days
```
Dimensions: page, device
Metrics: clicks, impressions, ctr, position (automatic)
Compare: mobile vs desktop performance differences
```

## Multi-Source Analysis Patterns

### 1. Content Performance Cross-Reference
**Purpose**: Compare search visibility with actual traffic
**GA4**: pagePath + screenPageViews, sessions
**GSC**: page + clicks, impressions, position
**Analysis**: Pages with high GSC impressions but low GA4 pageviews need optimization

### 2. Revenue vs Search Performance
**Purpose**: Understand which search terms drive revenue
**GA4**: pagePath, sessionSource + totalAdRevenue, screenPageViews
**GSC**: page, query + clicks, impressions, position
**Analysis**: High-revenue pages with poor search performance need SEO

## Query Optimization Tips

### Date Ranges
- **7 days**: Quick trend analysis, recent changes
- **30 days**: Standard business reporting, sufficient data volume  
- **90 days**: Seasonal trends, longer-term patterns
- **365 days**: Year-over-year comparisons, annual planning

### Data Filtering Best Practices
- **GA4**: Use property_id for specific sites, domain_filter for multi-domain setups
- **GSC**: Use domain parameter for specific sites, leave empty for all domains
- **Both**: Start with broader queries, then drill down with specific filters

### Result Interpretation
- **High impressions + Low CTR**: Title/meta description optimization needed
- **Good position + Low clicks**: SERP features may be stealing clicks
- **High GA4 traffic + Low GSC visibility**: Direct/social traffic, branded searches
- **High GSC impressions + Low GA4 traffic**: Technical SEO issues, poor UX
"""

@mcp.prompt("analyze_traffic_revenue")
async def analyze_traffic_revenue(timeframe: str = "30", property_id: str = "", domain: str = "") -> str:
    """
    Generate a comprehensive traffic vs revenue analysis prompt.
    
    This prompt guides AI analysis of GA4 data to identify revenue optimization opportunities
    by understanding which pages and traffic sources generate the most value.
    
    Args:
        timeframe: Number of days to analyze (default: 30)
        property_id: Specific GA4 property ID (optional)
        domain: Specific domain to analyze (optional)
    """
    from datetime import date, timedelta
    
    end_date = date.today()
    start_date = end_date - timedelta(days=int(timeframe))
    
    property_filter = f', property_id="{property_id}"' if property_id else ""
    domain_filter = f', domain_filter="{domain}"' if domain else ""
    
    return f"""
# Traffic vs Revenue Analysis - {timeframe} Day Report

## Objective
Analyze your website's traffic patterns and revenue generation to identify optimization opportunities and understand which content and traffic sources provide the most business value.

## Data Collection
Use these queries to gather the necessary data:

### 1. Page Revenue Performance
```
query_ga4_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="pagePath,deviceCategory",
    metrics="screenPageViews,totalAdRevenue,sessions,userEngagementDuration"{property_filter}{domain_filter}
)
```

### 2. Traffic Source Value
```
query_ga4_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="sessionSource,sessionMedium,country",
    metrics="sessions,totalUsers,totalAdRevenue,screenPageViews"{property_filter}{domain_filter}
)
```

## Analysis Framework

### Revenue Analysis
1. **Top Revenue Pages**: Identify pages generating the most ad revenue
2. **Revenue per Session**: Calculate revenue efficiency (totalAdRevenue ÷ sessions)
3. **Device Performance**: Compare revenue across desktop, mobile, tablet
4. **Engagement vs Revenue**: Correlate userEngagementDuration with revenue

### Traffic Source Analysis  
1. **High-Value Sources**: Which sources bring users who generate revenue?
2. **Geographic Performance**: Which countries provide the most valuable traffic?
3. **Channel Efficiency**: Compare organic, paid, social, direct traffic value
4. **Volume vs Value**: Balance high-traffic vs high-revenue sources

### Optimization Opportunities
1. **Undermonetized Traffic**: Pages with high traffic but low revenue
2. **Revenue Concentration**: Is revenue too dependent on few pages/sources?
3. **Device Optimization**: Are you losing revenue on mobile/desktop?
4. **Geographic Expansion**: Countries with good traffic but untapped revenue

## Key Metrics to Calculate
- **Revenue per Page View**: totalAdRevenue ÷ screenPageViews
- **Revenue per Session**: totalAdRevenue ÷ sessions  
- **Revenue per User**: totalAdRevenue ÷ totalUsers
- **Engagement Quality**: userEngagementDuration ÷ sessions

## Questions to Answer
1. Which 10 pages generate the most revenue? What makes them successful?
2. Which traffic sources provide the highest-quality (revenue-generating) users?
3. Are there high-traffic pages with surprisingly low revenue? Why?
4. How does mobile revenue performance compare to desktop?
5. Which geographic markets offer the best revenue potential?

## Actionable Recommendations
Based on your analysis, provide specific recommendations for:
- Content optimization priorities
- Traffic source investment decisions  
- Technical improvements for revenue optimization
- Geographic or device-specific strategies
"""

@mcp.prompt("discover_seo_opportunities")
async def discover_seo_opportunities(timeframe: str = "30", domain: str = "") -> str:
    """
    Generate a comprehensive SEO opportunity discovery prompt.
    
    This prompt guides AI analysis of GSC data to identify pages and keywords
    with high potential for traffic growth through optimization.
    
    Args:
        timeframe: Number of days to analyze (default: 30)
        domain: Specific domain to analyze (optional)
    """
    from datetime import date, timedelta
    
    end_date = date.today()
    start_date = end_date - timedelta(days=int(timeframe))
    
    domain_filter = f', domain="{domain}"' if domain else ""
    
    return f"""
# SEO Opportunity Discovery - {timeframe} Day Analysis

## Objective
Identify high-potential SEO opportunities by analyzing search performance data to find pages and keywords that could significantly increase your organic traffic with targeted optimization.

## Data Collection
Use these queries to gather comprehensive SEO intelligence:

### 1. Page Performance Analysis
```
query_gsc_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="page,country,device",
    search_type="web"{domain_filter}
)
```

### 2. Keyword Opportunity Analysis
```
query_gsc_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="query,country,device",
    search_type="web"{domain_filter}
)
```

### 3. Page-Keyword Optimization Opportunities
```
query_gsc_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="page,query",
    search_type="web"{domain_filter}
)
```

## Analysis Framework

### High-Priority Opportunities (Quick Wins)
1. **Position 11-30 Rankings**: Pages ranking on page 2-3 of Google
   - Filter: position between 11-30 AND impressions > 100
   - Potential: Moving to page 1 can increase traffic by 5-10x

2. **High Impressions, Low CTR**: Pages visible but not compelling
   - Filter: impressions > 500 AND ctr < 2%
   - Focus: Title and meta description optimization

3. **Good Position, Poor CTR**: SERP optimization opportunities
   - Filter: position < 10 AND ctr below industry average
   - Focus: Featured snippets, title optimization, SERP features

### Medium-Term Opportunities
1. **Keyword Gaps**: High-volume keywords with poor rankings
   - Filter: impressions > 200 AND position > 30
   - Focus: Content creation and optimization

2. **Device Performance Gaps**: Mobile vs desktop differences
   - Compare mobile and desktop performance for same pages
   - Focus: Mobile-specific optimization

3. **Geographic Opportunities**: Country-specific performance
   - Identify countries with high impressions but poor performance
   - Focus: Localization and geo-targeting

## Key Performance Indicators

### Opportunity Scoring
For each opportunity, calculate:
- **Potential Traffic**: impressions × (target_ctr - current_ctr)
- **Difficulty Score**: Current position (lower = easier)
- **Impact Score**: Current impressions × potential improvement
- **Priority**: High impact + Low difficulty = Top priority

### CTR Benchmarks by Position
- Position 1: 28-35% CTR
- Position 2: 15-20% CTR  
- Position 3: 10-15% CTR
- Position 4-10: 2-10% CTR
- Position 11+: <2% CTR

## Optimization Actions

### Quick Wins (1-2 weeks)
1. **Title Optimization**: Improve titles for high-impression, low-CTR pages
2. **Meta Descriptions**: Write compelling descriptions for high-position pages
3. **Internal Linking**: Boost pages ranking positions 11-30

### Content Optimization (1-2 months)
1. **Content Enhancement**: Expand thin content for pages with good rankings
2. **Keyword Integration**: Naturally integrate target keywords
3. **User Intent Alignment**: Ensure content matches search intent

### Technical SEO (2-3 months)
1. **Page Speed**: Optimize loading times for high-opportunity pages
2. **Mobile Experience**: Improve mobile usability and performance
3. **Schema Markup**: Add structured data for SERP features

## Questions to Answer
1. Which 10 pages have the highest traffic potential with minimal effort?
2. What keywords are you "almost ranking" for that could drive significant traffic?
3. Are there systematic CTR issues across certain types of pages?
4. Which geographic markets offer untapped SEO potential?
5. How does your mobile SEO performance compare to desktop?

## Expected Outcomes
Provide specific, prioritized recommendations including:
- Top 10 pages to optimize first (with expected traffic impact)
- Keyword opportunities ranked by potential and difficulty
- Technical SEO issues affecting multiple pages
- Content creation opportunities based on keyword gaps
- Timeline and resource requirements for implementation
"""

@mcp.prompt("analyze_page_performance")
async def analyze_page_performance(timeframe: str = "30", source: str = "both", property_id: str = "", domain: str = "") -> str:
    """
    Generate a comprehensive page performance analysis prompt.
    
    This prompt guides AI analysis to understand how individual pages perform
    across traffic, engagement, and search visibility metrics.
    
    Args:
        timeframe: Number of days to analyze (default: 30)
        source: Data source - "ga4", "gsc", or "both" (default: both)
        property_id: Specific GA4 property ID (optional)
        domain: Specific domain to analyze (optional)
    """
    from datetime import date, timedelta
    
    end_date = date.today()
    start_date = end_date - timedelta(days=int(timeframe))
    
    property_filter = f', property_id="{property_id}"' if property_id else ""
    domain_filter_ga4 = f', domain_filter="{domain}"' if domain else ""
    domain_filter_gsc = f', domain="{domain}"' if domain else ""
    
    queries = []
    
    if source in ["ga4", "both"]:
        queries.append(f"""
### GA4 Page Performance Data
```
query_ga4_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="pagePath,deviceCategory",
    metrics="screenPageViews,sessions,userEngagementDuration,bounceRate,totalUsers"{property_filter}{domain_filter_ga4}
)
```""")
    
    if source in ["gsc", "both"]:
        queries.append(f"""
### GSC Page Performance Data  
```
query_gsc_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="page,device",
    search_type="web"{domain_filter_gsc}
)
```""")
    
    queries_section = "\n".join(queries)
    
    return f"""
# Page Performance Analysis - {timeframe} Day Deep Dive

## Objective
Conduct a comprehensive analysis of individual page performance to identify top performers, underperformers, and optimization opportunities across traffic, engagement, and search visibility.

## Data Collection
{queries_section}

## Analysis Framework

### Page Performance Metrics

#### Traffic & Engagement (GA4)
1. **Page Views**: Total screenPageViews per page
2. **User Engagement**: userEngagementDuration per page
3. **Bounce Rate**: Percentage of single-page sessions
4. **Device Performance**: How pages perform across desktop/mobile/tablet
5. **Session Quality**: sessions and totalUsers per page

#### Search Visibility (GSC)
1. **Search Impressions**: How often pages appear in search results
2. **Click Performance**: clicks and click-through rates
3. **Ranking Positions**: Average position in search results
4. **Device Search Performance**: Mobile vs desktop search performance

### Performance Classification

#### Star Performers (Top 10%)
- High traffic AND high engagement
- Strong search visibility with good CTRs
- Consistent performance across devices
- Analysis: What makes these pages successful?

#### Hidden Gems (High Potential)
- Good search impressions but low clicks (GSC)
- High bounce rate but good traffic (GA4)
- Strong desktop but weak mobile performance
- Analysis: Quick optimization opportunities

#### Underperformers (Bottom 20%)
- Low traffic despite good search visibility
- High bounce rates with poor engagement
- Declining search positions
- Analysis: Need significant improvement or consider removal

#### Device-Specific Issues
- Pages with mobile vs desktop performance gaps
- Device-specific bounce rate problems
- Mobile search vs mobile traffic discrepancies

## Key Calculations

### Performance Ratios
- **Engagement Rate**: (1 - bounceRate) × 100
- **Traffic Efficiency**: screenPageViews ÷ sessions
- **Search-to-Traffic Ratio**: GA4 pageviews ÷ GSC clicks
- **Mobile Performance Index**: mobile_metrics ÷ desktop_metrics

### Opportunity Scores
- **SEO Opportunity**: (impressions × position_improvement_potential) ÷ 100
- **Engagement Opportunity**: potential_engagement_gain × current_traffic
- **Device Optimization**: |mobile_performance - desktop_performance|

## Analysis Questions

### Content Performance
1. Which pages have the highest user engagement and why?
2. What characteristics do your top-performing pages share?
3. Which pages have traffic but poor engagement (optimization candidates)?
4. Are there pages with good search visibility but poor traffic conversion?

### Technical Performance  
1. Do mobile and desktop versions of pages perform similarly?
2. Are there systematic bounce rate issues across certain page types?
3. Which pages load slowly or have poor user experience indicators?

### Search Performance
1. Which pages rank well but have poor click-through rates?
2. Are there pages with high impressions but low average positions?
3. Do your pages perform differently in mobile vs desktop search?

### Optimization Priorities
1. Which pages offer the highest ROI for optimization efforts?
2. Should any low-performing pages be improved, redirected, or removed?
3. Which successful page elements should be replicated elsewhere?

## Actionable Recommendations

### Quick Fixes (1-2 weeks)
- Title and meta description optimization for high-impression, low-CTR pages
- Internal linking improvements for pages with good content but poor visibility
- Mobile-specific issues affecting user experience

### Content Optimization (1-2 months)
- Content expansion for pages with good search visibility but poor engagement
- User experience improvements for high-traffic, high-bounce pages
- Device-specific content or layout optimization

### Strategic Changes (2+ months)
- Content consolidation or removal decisions for consistent underperformers
- New content creation based on successful page patterns
- Technical SEO improvements affecting multiple pages

## Success Metrics
Define specific, measurable outcomes:
- Target engagement improvements for identified pages
- Expected traffic increases from SEO optimizations
- Bounce rate reduction goals for problematic pages
- Mobile vs desktop performance parity objectives
"""

@mcp.prompt("multi_source_overview")
async def multi_source_overview(timeframe: str = "30", property_id: str = "", domain: str = "") -> str:
    """
    Generate a comprehensive multi-source analysis prompt combining GA4 and GSC data.
    
    This prompt guides AI analysis to understand the complete picture of website
    performance by combining traffic analytics with search performance data.
    
    Args:
        timeframe: Number of days to analyze (default: 30)  
        property_id: Specific GA4 property ID (optional)
        domain: Specific domain to analyze (optional)
    """
    from datetime import date, timedelta
    
    end_date = date.today()
    start_date = end_date - timedelta(days=int(timeframe))
    
    property_filter = f', property_id="{property_id}"' if property_id else ""
    domain_filter_ga4 = f', domain_filter="{domain}"' if domain else ""
    domain_filter_gsc = f', domain="{domain}"' if domain else ""
    
    return f"""
# Multi-Source Website Performance Overview - {timeframe} Days

## Objective
Create a comprehensive understanding of your website's performance by combining Google Analytics 4 traffic data with Google Search Console search performance data to identify opportunities and insights that neither source alone can provide.

## Data Collection Strategy

### 1. GA4 Traffic & Engagement Data
```
query_ga4_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="pagePath,sessionSource,deviceCategory",
    metrics="screenPageViews,sessions,totalUsers,userEngagementDuration,bounceRate"{property_filter}{domain_filter_ga4}
)
```

### 2. GSC Search Performance Data
```
query_gsc_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="page,query,device",
    search_type="web"{domain_filter_gsc}
)
```

### 3. GA4 Revenue Analysis (if applicable)
```
query_ga4_data(
    start_date="{start_date}",
    end_date="{end_date}",
    dimensions="pagePath,sessionSource",
    metrics="totalAdRevenue,publisherAdClicks,screenPageViews,sessions"{property_filter}{domain_filter_ga4}
)
```

## Cross-Platform Analysis Framework

### 1. Search-to-Traffic Correlation
**Purpose**: Understand how search visibility translates to actual traffic

#### Key Comparisons:
- **GSC Clicks vs GA4 Organic Sessions**: Should be roughly equal
- **High GSC Impressions + Low GA4 Traffic**: SEO opportunity or technical issues
- **High GA4 Traffic + Low GSC Visibility**: Non-search traffic sources dominant

#### Analysis Questions:
1. Which pages get good search impressions but poor traffic conversion?
2. Are there pages with high GA4 traffic but poor search visibility?
3. Do mobile and desktop show consistent patterns across both platforms?

### 2. Traffic Source Intelligence
**Purpose**: Understand the complete traffic acquisition picture

#### Multi-Source Attribution:
- **Organic Search Performance**: GSC data + GA4 organic traffic
- **Paid vs Organic**: GA4 sessionMedium analysis  
- **Direct Traffic Analysis**: High GA4 direct traffic might indicate strong brand search
- **Social & Referral Impact**: Non-search traffic driving engagement

#### Analysis Questions:
1. What percentage of your traffic comes from organic search vs other sources?
2. Which traffic sources provide the highest-quality users?
3. Are there opportunities to improve search performance for high-value pages?

### 3. Content Performance Insights
**Purpose**: Identify content optimization opportunities using both datasets

#### Performance Categories:
- **SEO Stars**: High GSC performance + High GA4 engagement
- **Hidden Gems**: Good GSC impressions + Poor GA4 metrics (optimization opportunity)
- **Traffic Drivers**: High GA4 traffic + Poor GSC performance (diversified success)
- **Underperformers**: Poor performance in both GSC and GA4

#### Analysis Questions:
1. Which content topics perform best across search and engagement?
2. Are there pages with good search rankings but poor user engagement?
3. Which pages show potential for improved search optimization?

### 4. Device & User Experience Analysis
**Purpose**: Optimize for different user contexts and devices

#### Cross-Platform Device Analysis:
- **Mobile Experience**: GSC mobile clicks vs GA4 mobile engagement
- **Desktop Performance**: Compare desktop search and traffic patterns
- **Device-Specific Issues**: Bounce rates, engagement times by device

#### Analysis Questions:
1. Is your mobile search performance reflected in mobile user engagement?
2. Are there device-specific user experience issues?
3. Which devices provide the best overall performance?

## Key Performance Indicators (KPIs)

### Primary Metrics
- **Total Organic Traffic**: GA4 organic sessions + Direct traffic correlation
- **Search Efficiency**: GSC clicks ÷ GA4 organic pageviews (should be close to 1.0)
- **Overall Engagement**: Average session duration across traffic sources
- **Revenue Performance**: Revenue per source vs search performance

### Diagnostic Metrics
- **Search Gap**: High GSC impressions but low GA4 traffic
- **Engagement Gap**: High traffic but poor engagement metrics
- **Device Gap**: Mobile vs desktop performance differences
- **Source Diversity**: Traffic distribution across different channels

## Analysis Outputs

### Executive Summary
Provide a high-level overview including:
- Total website traffic and search performance
- Primary traffic sources and their quality
- Top performing content across both platforms
- Major opportunities identified

### Opportunity Matrix
Categorize findings into:

#### High Impact, Low Effort (Quick Wins)
- Pages with good search impressions but poor CTR
- Technical issues affecting search-to-traffic conversion
- Mobile experience improvements

#### High Impact, High Effort (Strategic Projects)
- Content gaps identified through search data
- Major user experience improvements
- New content creation based on search opportunities

#### Monitoring & Maintenance
- Consistent performers to maintain
- Seasonal or trending topics to watch
- Performance tracking for implemented changes

### Specific Recommendations

#### SEO Improvements
- Title and meta description optimization priorities
- Content enhancement opportunities
- Technical SEO issues affecting traffic

#### User Experience Enhancements  
- Pages with high traffic but poor engagement
- Mobile-specific optimization needs
- Site structure and navigation improvements

#### Content Strategy
- Topics with high search potential but low current performance
- Content types that perform well across both search and engagement
- Content gaps identified through competitive search analysis

## Success Measurement

### Short-term Goals (1-3 months)
- Improve search-to-traffic conversion rates
- Increase engagement metrics for high-traffic pages
- Optimize mobile experience based on device performance gaps

### Long-term Goals (3-12 months)
- Increase overall organic traffic share
- Improve revenue per session across traffic sources
- Establish consistent top performance across both GA4 and GSC metrics

## Reporting Schedule
- **Weekly**: Monitor key changes and quick wins implementation
- **Monthly**: Comprehensive cross-platform performance review
- **Quarterly**: Strategic assessment and goal adjustment
"""

# Security middleware for HTTP mode with enhanced logging and rate limiting
class BearerTokenMiddleware:
    """Middleware to authenticate incoming HTTP requests using header or ?key= param.

    Uses helpers in `mcp_auth` for parsing and stripping the query param.
    """
    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key
        self.logger = logging.getLogger(f"{__name__}.BearerTokenMiddleware")

        # Rate limiting config
        self.rate_limit_window = 60
        self.rate_limit_requests = 100
        self.ip_requests: Dict[str, list] = {}

        self.auth_stats = {
            'total_requests': 0,
            'header_auth': 0,
            'url_param_auth': 0,
            'auth_failures': 0,
            'rate_limited': 0
        }

    def _cleanup_rate_limit_data(self):
        current_time = time.time()
        cutoff_time = current_time - self.rate_limit_window
        for ip in list(self.ip_requests.keys()):
            self.ip_requests[ip] = [t for t in self.ip_requests[ip] if t > cutoff_time]
            if not self.ip_requests[ip]:
                del self.ip_requests[ip]

    def _is_rate_limited(self, client_ip: str) -> bool:
        self._cleanup_rate_limit_data()
        now = time.time()
        if client_ip not in self.ip_requests:
            self.ip_requests[client_ip] = []
        cutoff = now - self.rate_limit_window
        recent = [t for t in self.ip_requests[client_ip] if t > cutoff]
        return len(recent) >= self.rate_limit_requests

    async def __call__(self, scope, receive, send):
        # Only handle HTTP
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive)
        client_ip = request.client.host if request.client else 'unknown'
        method = request.method
        path = request.url.path

        request_id = str(uuid.uuid4())[:8]
        set_request_context(request_id)
        request_tracker.start_request(request_id, client_ip, method, path)
        self.auth_stats['total_requests'] += 1

        # Handle CORS preflight
        if method == "OPTIONS":
            origin = request.headers.get("origin", "*")
            cors_headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, X-API-Key, X-Auth-Token",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "86400",
            }
            response = JSONResponse(status_code=200, content={"message": "CORS preflight OK"}, headers=cors_headers)
            request_tracker.end_request(request_id, 200)
            await response(scope, receive, send)
            return

        # Rate limiting
        if self._is_rate_limited(client_ip):
            self.auth_stats['rate_limited'] += 1
            self.logger.warning(f"Rate limit exceeded for {client_ip}")
            response = JSONResponse(status_code=429, content={
                "error": "Rate limit exceeded",
                "message": f"Too many requests from {client_ip}. Limit: {self.rate_limit_requests} per {self.rate_limit_window}s",
                "request_id": request_id
            })
            request_tracker.end_request(request_id, 429, "Rate limit exceeded")
            await response(scope, receive, send)
            return

        # Debug: headers and query
        headers_debug = dict(request.headers)
        self.logger.info(f"[{request_id}] Headers: {headers_debug}")
        self.logger.info(f"[{request_id}] Query params: {dict(request.query_params)}")

        # Parse authentication
        key_from_header, key_from_query, _raw = extract_keys_from_request(request)
        token, auth_method = determine_token(key_from_header, key_from_query)
        if auth_method == 'header':
            self.auth_stats['header_auth'] += 1
        elif auth_method == 'url_param':
            self.auth_stats['url_param_auth'] += 1
            if not hasattr(self, '_logged_url_param_ips'):
                self._logged_url_param_ips = set()
            if client_ip not in self._logged_url_param_ips:
                self._logged_url_param_ips.add(client_ip)
                self.logger.info(f"Using URL parameter authentication from {client_ip}")

        # If both provided and equal, remove key from query for downstream
        if key_from_header and key_from_query and key_from_header == key_from_query:
            strip_key_param_from_scope(request)

        # No auth
        if not token:
            self.auth_stats['auth_failures'] += 1
            self.logger.warning(f"[{request_id}] No authentication provided from {client_ip}")
            response = JSONResponse(status_code=401, content={
                "error": "Authentication required",
                "message": "Provide Authorization: Bearer <token> or ?key=<token>",
                "request_id": request_id
            })
            request_tracker.end_request(request_id, 401, "No authentication")
            await response(scope, receive, send)
            return

        # Validate token
        if not secure_compare(token, self.api_key):
            self.auth_stats['auth_failures'] += 1
            self.logger.warning(f"[{request_id}] Invalid API key via {auth_method} from {client_ip}")
            response = JSONResponse(status_code=401, content={"error": "Invalid API key", "request_id": request_id})
            request_tracker.end_request(request_id, 401, "Invalid API key")
            await response(scope, receive, send)
            return

        # Success: forward request and attach CORS headers on response
        self.logger.info(f"[{request_id}] Authentication successful via {auth_method} from {client_ip}")

        async def tracking_send(message):
            if message.get("type") == "http.response.start":
                status_code = message.get("status")
                if "headers" not in message:
                    message["headers"] = []
                origin = request.headers.get("origin", "*")
                cors = [
                    (b"access-control-allow-origin", origin.encode()),
                    (b"access-control-allow-credentials", b"true"),
                    (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
                    (b"access-control-allow-headers", b"Authorization, Content-Type, Accept, X-API-Key, X-Auth-Token")
                ]
                existing = [h[0].lower() for h in message["headers"]]
                for name, val in cors:
                    if name not in existing:
                        message["headers"].append((name, val))
                request_tracker.end_request(request_id, status_code)
            await send(message)

        await self.app(scope, receive, tracking_send)

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="GA4 & GSC MCP Server")
    parser.add_argument("--http", action="store_true", help="Run as HTTP server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for all routines")
    parser.add_argument("--key", type=str, help="API key for authentication (if not provided, a random key will be generated)")
    parser.add_argument("--simple", action="store_true", help="Run in simple mode with minimal tools and enhanced documentation")
    args = parser.parse_args()

    # Generate API key if not provided
    api_key = args.key if args.key else secrets.token_urlsafe(32)

    # Set simple mode flag and conditionally filter tools
    SIMPLE_MODE = args.simple

    def print_github_copilot_mcp_config(host, port, api_key, scheme="http"):
        # If host is 0.0.0.0, suggest localhost for local, or let user replace with public/tunnel hostname
        display_host = host if host != "0.0.0.0" else "localhost"
        url = f"{scheme}://{display_host}:{port}/mcp"
        
        if SIMPLE_MODE:
            tools = [
                "list_ga4_properties",
                "list_gsc_domains",
                "query_ga4_data", 
                "query_gsc_data"
            ]
            mode_description = "Simple Mode - Core Tools Only"
        else:
            tools = [
                "query_ga4_data",
                "query_gsc_data", 
                # "query_unified_data",
                "list_ga4_properties",
                "list_gsc_domains",
                "page_performance_ga4",
                "traffic_sources_ga4",
                "audience_analysis_ga4", 
                "revenue_analysis_ga4",
                "page_performance_gsc",
                "query_analysis_gsc",
                "page_query_opportunities_gsc",
                "get_server_stats",
                "invalidate_cache",
                "debug_request_headers"
            ]
            mode_description = "Full Mode - All Tools Available"
            
        print(f"\n🔗 Sample mcpServers config for GitHub Copilot coding agent - {mode_description} (RECOMMENDED - Local/Direct):\n")
        print("{")
        print('  "mcpServers": {')
        print('    "ga4-gsc-mcp": {')
        print('      "type": "http",')
        print(f'      "url": "{url}",')
        print(f'      "headers": {{')
        print(f'        "Authorization": "Bearer {api_key}"')
        print(f'      }},')
        
        if SIMPLE_MODE:
            print('      "resources": [')
            print('        "ga4://dimensions-metrics-reference",')
            print('        "gsc://dimensions-metrics-reference",')
            print('        "business://common-query-patterns"')
            print('      ],')
            print('      "prompts": [')
            print('        "analyze_traffic_revenue",')
            print('        "discover_seo_opportunities",')
            print('        "analyze_page_performance",')
            print('        "multi_source_overview"')
            print('      ],')
        
        print('      "tools": [')
        for i, tool in enumerate(tools):
            comma = "," if i < len(tools) - 1 else ""
            print(f'        "{tool}"{comma}')
        print('      ]')
        print('    }')
        print('  }')
        print('}')
        
        if SIMPLE_MODE:
            print("➡️  Simple mode with core tools + documentation resources and analysis prompts\n")
        else:
            print("➡️  Use this for direct connections (localhost or when Authorization headers work)\n")
        
        # Add Cloudflare tunnel configuration
        print("🔗 Alternative config for Cloudflare tunnels/proxies (RECOMMENDED - Custom Header):\n")
        print("{")
        print('  "mcpServers": {')
        print('    "ga4-gsc-mcp": {')
        print('      "type": "http",')
        print(f'      "url": "{url}",')
        print(f'      "headers": {{')
        print(f'        "X-API-Key": "{api_key}"')
        print(f'      }},')
        
        if SIMPLE_MODE:
            print('      "resources": [')
            print('        "ga4://dimensions-metrics-reference",')
            print('        "gsc://dimensions-metrics-reference",')
            print('        "business://common-query-patterns"')
            print('      ],')
            print('      "prompts": [')
            print('        "analyze_traffic_revenue",')
            print('        "discover_seo_opportunities",')
            print('        "analyze_page_performance",')
            print('        "multi_source_overview"')
            print('      ],')
        
        print('      "tools": [')
        for i, tool in enumerate(tools):
            comma = "," if i < len(tools) - 1 else ""
            print(f'        "{tool}"{comma}')
        print('      ]')
        print('    }')
        print('  }')
        print('}')
        print("➡️  Use this when Authorization headers are stripped by proxies/tunnels\n")
        
        # Add fallback configuration for clients that don't support Authorization headers
        url_with_key = f"{scheme}://{display_host}:{port}/mcp?key={api_key}"
        print("🔗 Alternative config for clients that don't support Authorization headers (FALLBACK - URL Auth):\n")
        print("{")
        print('  "mcpServers": {')
        print('    "ga4-gsc-mcp": {')
        print('      "type": "http",')
        print(f'      "url": "{url_with_key}",')
        
        if SIMPLE_MODE:
            print('      "resources": [')
            print('        "ga4://dimensions-metrics-reference",')
            print('        "gsc://dimensions-metrics-reference",')
            print('        "business://common-query-patterns"')
            print('      ],')
            print('      "prompts": [')
            print('        "analyze_traffic_revenue",')
            print('        "discover_seo_opportunities",')
            print('        "analyze_page_performance",')
            print('        "multi_source_overview"')
            print('      ],')
        
        print('      "tools": [')
        for i, tool in enumerate(tools):
            comma = "," if i < len(tools) - 1 else ""
            print(f'        "{tool}"{comma}')
        print('      ]')
        print('    }')
        print('  }')
        print('}')
        print("⚠️  URL-based auth exposes the key in logs. Use header auth when possible.\n")
    # Patch: Set a global debug flag and patch all tool functions to pass debug if not explicitly set
    DEBUG_FLAG = args.debug

    # Filter tools based on simple mode
    if SIMPLE_MODE:
        # In simple mode, only register the core 4 tools
        simple_tools = [
            "list_ga4_properties",
            "list_gsc_domains", 
            "query_ga4_data",
            "query_gsc_data"
        ]
        
        # Patch only the core tools to inject debug if not set
        for tool_name in simple_tools:
            orig_func = getattr(mcp, tool_name, None)
            if orig_func is not None:
                async def wrapper(*a, __orig_func=orig_func, **kw):
                    if 'debug' not in kw:
                        kw['debug'] = DEBUG_FLAG
                    return await __orig_func(*a, **kw)
                setattr(mcp, tool_name, wrapper)
    else:
        # Patch all mcp.tool functions to inject debug if not set
        import functools
        for tool_name in [
            "query_ga4_data",
            "query_gsc_data",
            # "query_unified_data",
            "list_ga4_properties",
            "list_gsc_domains",
            "page_performance_ga4",
            "traffic_sources_ga4", 
            "audience_analysis_ga4",
            "revenue_analysis_ga4",
            "page_performance_gsc",
            "query_analysis_gsc",
            "page_query_opportunities_gsc",
            "get_server_stats",
            "invalidate_cache",
            "debug_request_headers"
        ]:
            orig_func = getattr(mcp, tool_name, None)
            if orig_func is not None:
                async def wrapper(*a, __orig_func=orig_func, **kw):
                    if 'debug' not in kw:
                        kw['debug'] = DEBUG_FLAG
                    return await __orig_func(*a, **kw)
                setattr(mcp, tool_name, wrapper)

    if args.http:
        print(f"Starting MCP HTTP server on {args.host}:{args.port}")
        print_github_copilot_mcp_config(args.host, args.port, api_key, scheme="http")
        import uvicorn
        # Suppress noisy ClosedResourceError stacktraces from internal streamable HTTP code
        try:
            import anyio
        except Exception:
            anyio = None

        class _ClosedResourceFilter(logging.Filter):
            def filter(self, record):
                # If there is no exception info, keep the record
                ei = getattr(record, 'exc_info', None)
                if not ei:
                    return True
                exc = ei[1]
                try:
                    if anyio is not None and isinstance(exc, anyio.ClosedResourceError):
                        # Suppress this particular exception to avoid noisy stacktraces
                        return False
                except Exception:
                    pass
                return True

        stream_logger = logging.getLogger('mcp.server.streamable_http')
        stream_logger.addFilter(_ClosedResourceFilter())
        
        # Create the streamable HTTP app and add authentication middleware
        app = mcp.streamable_http_app()
        
        # Use the improved BearerTokenMiddleware with secure comparison and logging
        middleware = BearerTokenMiddleware(app, api_key)
        
        logger.info(f"MCP server starting with enhanced monitoring and security features")
        logger.info(f"Rate limiting: {middleware.rate_limit_requests} requests per {middleware.rate_limit_window} seconds per IP")
        
        uvicorn.run(middleware, host=args.host, port=args.port)
    else:
        print("Starting MCP stdio server")
        mcp.run()

    #ok
    