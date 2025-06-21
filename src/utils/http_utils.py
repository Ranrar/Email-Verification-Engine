"""
Email Verification Engine - HTTP Utility Functions
=====================
HTTP-related utility functions including User-Agent generation,
request handling, and other common HTTP operations.
"""
import requests
from src.helpers.dbh import sync_db
from src.managers.log import get_logger

logger = get_logger()

def get_user_agent():
    """
    Retrieves User-Agent configuration from database and formats it properly.
    If database connection fails, returns a minimal user agent.
    
    Returns:
        str: Formatted User-Agent string from database settings
    """
    try:
        # Try to fetch User-Agent settings from database
        rows = sync_db.fetch("""
            SELECT name, value FROM app_settings
            WHERE category = 'http' AND sub_category = 'user_agent'
        """)

        # If no results were returned, raise an exception
        if not rows:
            raise ValueError("No user agent settings found in database")

        # Collect values from database
        settings = {row['name']: row['value'] for row in rows}
        
        # Check for required fields
        if 'name' not in settings:
            raise ValueError("User agent name not found in database")
            
        # Build user-agent string based on available settings
        name = settings.get('name')
        version = settings.get('version', '')
        url = settings.get('url', '')
        
        if version and url:
            return f"{name}/{version} ({url})"
        elif version:
            return f"{name}/{version}"
        else:
            return name
            
    except Exception as e:
        # Log error but don't reference database in error message
        logger.error(f"Failed to retrieve User-Agent settings: {str(e)}")
        
        # Return minimal, non-revealing user agent
        return "Mozilla/5.0 (compatible)"

def get_request_headers():
    """
    Returns standardized headers for HTTP requests.
    
    Returns:
        dict: Dictionary of HTTP headers
    """
    return {
        "User-Agent": get_user_agent(),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9"
    }

def make_request(url, method="GET", timeout=5, headers=None, params=None, json_data=None):
    """
    Makes an HTTP request with standardized error handling and logging.
    
    Args:
        url (str): The URL to request
        method (str): HTTP method (GET, POST, etc.)
        timeout (int): Request timeout in seconds
        headers (dict): Optional custom headers to include
        params (dict): Optional URL parameters
        json_data (dict): Optional JSON data for POST/PUT requests
        
    Returns:
        dict: Response data and metadata
    """
    request_headers = get_request_headers()
    
    # Merge with custom headers if provided
    if headers:
        request_headers.update(headers)
        
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=request_headers,
            timeout=timeout,
            params=params,
            json=json_data
        )
        
        # Try to parse JSON response
        try:
            data = response.json()
        except ValueError:
            data = response.text
            
        return {
            "success": response.status_code < 400,
            "status_code": response.status_code,
            "data": data,
            "headers": dict(response.headers)
        }
        
    except Exception as e:
        logger.error(f"Request to {url} failed: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }