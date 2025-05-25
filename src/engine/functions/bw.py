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
from src.managers.log import Axe

logger = Axe()

def check_black_white(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if a domain is whitelisted or blacklisted.
    
    Args:
        context: A dictionary containing email and other validation context
        
    Returns:
        dict: Result dictionary with domain filter status
    """
    email = context.get('email')
    if not email or '@' not in email:
        return {
            'valid': False,
            'error': 'Invalid email format',
            'step': 'domain_filter_check'
        }
    
    # Extract domain from email
    domain = email.split('@')[1].lower()
    
    # Check cache first
    filter_status = _check_cache_for_domain_status(domain)
    if filter_status:
        logger.debug(f"Domain filter cache hit for {domain}")
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
    # Query database for domain status using the new black_white table
    query = """
        SELECT domain, category, timestamp, added_by 
        FROM black_white 
        WHERE domain = $1
    """
    domain_info = sync_db.fetchrow(query, domain)
    
    if not domain_info:
        # Domain not found in filters, continue validation
        logger.debug(f"Domain {domain} not found in filters, proceeding with validation")
        return {
            'valid': True,
            'whitelisted': False,
            'blacklisted': False,
            'step': 'domain_filter_check'
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
            'step': 'domain_filter_check',
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
            'step': 'domain_filter_check',
            'source': added_by
        }
    
    # Default case - should not reach here if database is properly structured
    return {
        'valid': True,
        'whitelisted': False,
        'blacklisted': False,
        'step': 'domain_filter_check'
    }

def _cache_domain_status(domain: str, result: Dict[str, Any]) -> None:
    """Cache the domain status for future queries"""
    from src.managers.rate_limit import rate_limit_manager
    
    try:
        # Get appropriate cache TTL from rate limit manager
        ttl = rate_limit_manager.get_cache_limit('domain_filters_ttl')
    except Exception as e:
        logger.debug(f"Failed to get cache TTL from rate limit manager: {e}")
        # Default to 1 hour if rate limit manager fails
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
        dict: Domain status information
    """
    # Simply reuse the database check function
    return _check_database_for_domain_status(domain)
