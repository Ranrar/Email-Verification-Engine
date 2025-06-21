"""
Email Verification Engine
=====================
Black and whitelist checking

This module provides functions to check if a domain is:
1. Whitelisted - Continue validation process
2. Blacklisted - Stop validation and return error
"""

from typing import Dict, Any, Optional
from src.helpers.dbh import sync_db
from src.managers.cache import cache_manager, CacheKeys
from src.managers.log import get_logger

logger = get_logger()

def check_black_white(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if a domain is whitelisted or blacklisted.
    
    Args:
        context: A dictionary containing email and other validation context
        
    Returns:
        dict: Result dictionary with domain status
    """
    email = context.get('email')
    if not email or '@' not in email:
        return {
            'valid': False,
            'error': 'Invalid email format'
        }
    
    # Extract domain from email
    domain = email.split('@')[1].lower()
    
    # Check cache first
    filter_status = _check_cache_for_domain_status(domain)
    if filter_status:
        logger.debug(f"Domain cache hit for {domain}")
        return filter_status
    
    # Query database if not in cache
    result = _check_database_for_domain_status(domain)
    
    # Cache the result for future queries
    _cache_domain_status(domain, result)
    
    return result

def _check_cache_for_domain_status(domain: str) -> Optional[Dict[str, Any]]:
    """Check if domain status is already in cache"""
    cache_key = CacheKeys.blacklist(domain)
    cached_result = cache_manager.get(cache_key)
    
    if cached_result is not None:
        return cached_result
    return None

def _check_database_for_domain_status(domain: str) -> Dict[str, Any]:
    """Query database for domain status"""
    query = """
        SELECT domain, category, timestamp, added_by 
        FROM black_white 
        WHERE domain = $1
    """
    domain_info = sync_db.fetchrow(query, domain)
    
    if not domain_info:
        # Domain not found in filters, continue validation
        logger.debug(f"Domain {domain} not in black/white list, proceeding")
        return {
            'valid': True,
            'whitelisted': False,
            'blacklisted': False
        }
        
    # Process the result based on category
    category = domain_info['category']
    added_by = domain_info['added_by']
    
    # Handle whitelisted domain
    if category == 'whitelisted':
        logger.debug(f"Domain {domain} is whitelisted by {added_by}")
        return {
            'valid': True,
            'whitelisted': True,
            'blacklisted': False,
            'source': added_by
        }
        
    # Handle blacklisted domain
    if category == 'blacklisted':
        logger.info(f"Domain {domain} is blacklisted by {added_by}")
        return {
            'valid': False,
            'whitelisted': False,
            'blacklisted': True,
            'error': f'Domain {domain} is blacklisted',
            'source': added_by
        }
    
    # Default case - should not reach here if database is properly structured
    return {
        'valid': True,
        'whitelisted': False,
        'blacklisted': False
    }

def _cache_domain_status(domain: str, result: Dict[str, Any]) -> None:
    """Cache the domain status for future queries"""
    # Default to 1 hour cache TTL for domain status
    ttl = 3600
        
    # Cache the result
    cache_key = CacheKeys.blacklist(domain)
    cache_manager.set_with_ttl(cache_key, result, ttl) 

def get_domain_status(domain: str) -> Dict[str, Any]:
    """
    Get the current status of a domain
    
    Args:
        domain: Domain to check
        
    Returns:
        dict: Domain status information with keys:
            - valid: Whether the check succeeded
            - whitelisted: Whether domain is whitelisted
            - blacklisted: Whether domain is blacklisted
            - source: Source of the blacklist/whitelist (if applicable)
    """
    return _check_database_for_domain_status(domain)
