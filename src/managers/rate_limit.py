"""
Email Verification Engine
===================================
Rate Limit Manager:
This module handles all rate limiting settings for different EVE components.
It uses the consolidated rate_limit table in the PostgreSQL database.
"""

from typing import Any, Dict, Optional
from src.helpers.dbh import sync_db
from src.managers.log import get_logger
import threading
import time

logger = get_logger()

# Global lock for domain rate limiting
_rate_limiter_lock = threading.Lock()

# Global dictionary to track last connection times per domain
_domain_last_connection = {}

class RateLimitManager:
    """
    Central manager for rate limits across the EVE system.
    Uses a singleton pattern to ensure only one instance exists.
    """
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super(RateLimitManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
    
        # Initialize category-specific rate limit caches
        self.smtp_limits = None
        self.dom_mx_limits = None  
        self.auth_security_limits = None
        self.additional_limits = None
        self.cache_limits = None
        self.dns_limits = None

        # Add test_mode attribute (default: False)
        self.test_mode = False

        # No initial loading - will load on demand
        logger.info("Rate limit manager initialized with lazy loading")
    
    def _load_smtp_limits(self):
        """Load SMTP rate limits from database"""
        if self.smtp_limits is not None:
            logger.debug("SMTP rate limits already loaded, skipping reload")
            return
        
        try:
            # Query the consolidated rate_limit table filtering by category
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'smtp' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.smtp_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Convert to appropriate type based on is_time flag
                if is_time:
                    self.smtp_limits[name] = float(value)
                else:
                    self.smtp_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.smtp_limits)} SMTP rate limits")
        except Exception as e:
            logger.error(f"Failed to load SMTP rate limits: {str(e)}")
            self.smtp_limits = {}  # Initialize with empty dict on error
            raise
    
    def _load_dom_mx_limits(self):
        """Load domain and MX rate limits from database"""
        if self.dom_mx_limits is not None:
            logger.debug("Domain/MX rate limits already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'dom_mx' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.dom_mx_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Convert to appropriate type based on is_time flag
                if is_time:
                    self.dom_mx_limits[name] = float(value)
                else:
                    self.dom_mx_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.dom_mx_limits)} domain/MX rate limits")
        except Exception as e:
            logger.error(f"Failed to load domain/MX rate limits: {str(e)}")
            self.dom_mx_limits = {}
            raise
    
    def _load_auth_security_limits(self):
        """Load authentication and security rate limits from database"""
        if self.auth_security_limits is not None:
            logger.debug("Auth/Security rate limits already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'auth_security' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.auth_security_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Convert to appropriate type based on is_time flag
                if is_time:
                    self.auth_security_limits[name] = float(value)
                else:
                    self.auth_security_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.auth_security_limits)} authentication/security rate limits")
        except Exception as e:
            logger.error(f"Failed to load authentication/security rate limits: {str(e)}")
            self.auth_security_limits = {}
            raise
    
    def _load_additional_limits(self):
        """Load additional protocols rate limits from database"""
        if self.additional_limits is not None:
            logger.debug("Additional protocol rate limits already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'additional' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.additional_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Convert to appropriate type based on is_time flag
                if is_time:
                    self.additional_limits[name] = float(value)
                else:
                    self.additional_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.additional_limits)} additional protocol rate limits")
        except Exception as e:
            logger.error(f"Failed to load additional protocol rate limits: {str(e)}")
            self.additional_limits = {}
            raise
    
    def _load_cache_limits(self):
        """Load cache-related rate limits from database"""
        if self.cache_limits is not None:
            logger.debug("Cache rate limits already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'cache' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.cache_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Cache limits are all time-based
                self.cache_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.cache_limits)} cache rate limits")
        except Exception as e:
            logger.error(f"Failed to load cache rate limits: {str(e)}")
            self.cache_limits = {}
            raise
    
    def _load_dns_limits(self):
        """Load DNS-related rate limits from database"""
        if self.dns_limits is not None:
            logger.debug("DNS rate limits already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT name, value, is_time, enabled 
                FROM rate_limit 
                WHERE category = 'dns' AND enabled = TRUE
            """
            results = sync_db.fetch(query)
            
            self.dns_limits = {}
            for row in results:
                name = row['name']
                value = row['value']
                is_time = row['is_time']
                
                # Convert to appropriate type based on is_time flag
                if is_time:
                    self.dns_limits[name] = float(value)
                else:
                    self.dns_limits[name] = int(value)
                    
            logger.debug(f"Loaded {len(self.dns_limits)} DNS rate limits")
        except Exception as e:
            logger.error(f"Failed to load DNS rate limits: {str(e)}")
            self.dns_limits = {}
            raise

    def reload_all_limits(self):
        """Reload all rate limits from database"""
        self.smtp_limits = None
        self.dom_mx_limits = None
        self.auth_security_limits = None
        self.additional_limits = None
        self.cache_limits = None
        self.dns_limits = None
        logger.info("All rate limits marked for reload")
        
    def get_smtp_limits(self) -> Dict[str, Any]:
        """Get all SMTP rate limits"""
        if self.smtp_limits is None:
            self._load_smtp_limits()
        if self.smtp_limits is None:
            return {}
        return self.smtp_limits
    
    def get_domain_mx_limits(self) -> Dict[str, Any]:
        """Get all domain and MX rate limits"""
        if self.dom_mx_limits is None:
            self._load_dom_mx_limits()
        if self.dom_mx_limits is None:
            return {}
        return self.dom_mx_limits
    
    def get_auth_security_limits(self) -> Dict[str, Any]:
        """Get all authentication and security rate limits"""
        if self.auth_security_limits is None:
            self._load_auth_security_limits()
        if self.auth_security_limits is None:
            return {}
        return self.auth_security_limits
    
    def get_additional_protocol_limits(self) -> Dict[str, Any]:
        """Get all additional protocols rate limits"""
        if self.additional_limits is None:
            self._load_additional_limits()
        if self.additional_limits is None:
            return {}
        return self.additional_limits
        
    def get_cache_limits(self) -> Dict[str, Any]:
        """Get all cache-related rate limits"""
        if self.cache_limits is None:
            self._load_cache_limits()
        if self.cache_limits is None:
            return {}
        return self.cache_limits
    
    def get_dns_limits(self) -> Dict[str, Any]:
        """Get all DNS rate limits"""
        if self.dns_limits is None:
            self._load_dns_limits()
        if self.dns_limits is None:
            return {}
        return self.dns_limits
    
    def get_smtp_limit(self, setting_name: str) -> Any:
        """Get a specific SMTP rate limit"""
        if self.smtp_limits is None:
            self._load_smtp_limits()
        
        # If setting exists, return it
        if self.smtp_limits is not None and setting_name in self.smtp_limits:
            return self.smtp_limits[setting_name]
        
        # If it's not found, raise an error
        logger.error(f"SMTP rate limit '{setting_name}' not found in database")
        raise KeyError(f"SMTP rate limit '{setting_name}' not found in database")

    def get_domain_mx_limit(self, setting_name: str) -> Any:
        """Get a specific domain/MX rate limit"""
        if self.dom_mx_limits is None:
            self._load_dom_mx_limits()
        
        # If setting exists, return it
        if self.dom_mx_limits is not None and setting_name in self.dom_mx_limits:
            return self.dom_mx_limits[setting_name]
        
        # If it's not found, raise an error
        logger.error(f"Domain/MX rate limit '{setting_name}' not found in database")
        raise KeyError(f"Domain/MX rate limit '{setting_name}' not found in database")
        
    def get_additional_protocol_limit(self, setting_name: str) -> Any:
        """Get a specific additional protocol rate limit"""
        if self.additional_limits is None:
            self._load_additional_limits()
        
        # If setting exists, return it
        if self.additional_limits is not None and setting_name in self.additional_limits:
            return self.additional_limits[setting_name]
        
        # If it's not found, raise an error
        logger.error(f"Additional protocol rate limit '{setting_name}' not found in database")
        raise KeyError(f"Additional protocol rate limit '{setting_name}' not found in database")
            
    def get_dns_limit(self, setting_name: str) -> Any:
        """Get a specific DNS rate limit"""
        if self.dns_limits is None:
            self._load_dns_limits()
        
        # If setting exists, return it
        if self.dns_limits is not None and setting_name in self.dns_limits:
            return self.dns_limits[setting_name]
        
        # If it's not found, raise an error
        logger.error(f"DNS rate limit '{setting_name}' not found in database")
        raise KeyError(f"DNS rate limit '{setting_name}' not found in database")

    # --- SMTP Rate Limit Helper Methods ---
    def get_max_retries(self):
        return self.get_smtp_limit('max_retries')

    def get_max_connections_per_minute(self):
        return self.get_smtp_limit('max_connections_per_minute')

    def get_max_connections_per_domain(self):
        return self.get_smtp_limit('max_connections_per_domain')

    def get_max_vrfy_per_minute(self):
        return self.get_smtp_limit('max_vrfy_per_minute')

    def get_max_mx_requests_per_minute(self):
        return self.get_smtp_limit('max_mx_requests_per_minute')

    def get_max_spf_dkim_dmarc_requests_per_minute(self):
        return self.get_smtp_limit('max_spf_dkim_dmarc_requests_per_minute')

    def get_max_banner_requests_per_minute(self):
        return self.get_smtp_limit('max_banner_requests_per_minute')

    def get_max_reverse_dns_requests_per_minute(self):
        return self.get_smtp_limit('max_reverse_dns_requests_per_minute')

    def get_max_whois_requests_per_minute(self):
        return self.get_smtp_limit('max_whois_requests_per_minute')
        
    # --- SMTP Timeout Helper Methods ---
    def get_connect_timeout(self):
        return self.get_smtp_limit('timeout_connect')
        
    def get_read_timeout(self):
        return self.get_smtp_limit('timeout_read')
        
    def get_overall_timeout(self):
        return self.get_smtp_limit('timeout_overall')

    # --- Cache Duration Helper Methods ---
    def get_cache_duration_mx_spf_dkim_dmarc(self):
        return self.get_cache_limit('cache_duration_mx_spf_dkim_dmarc')

    def get_cache_duration_reverse_dns(self):
        return self.get_cache_limit('cache_duration_reverse_dns')

    def get_cache_duration_banner(self):
        return self.get_cache_limit('cache_duration_banner')

    def get_cache_duration_smtp_result(self):
        return self.get_cache_limit('cache_duration_smtp_result')

    def get_cache_duration_smtp_vrfy(self):
        return self.get_cache_limit('cache_duration_smtp_vrfy')

    def get_cache_duration_smtp_port(self):
        return self.get_cache_limit('cache_duration_smtp_port')

    def get_cache_duration_whois(self):
        return self.get_cache_limit('cache_duration_whois')

    # --- Domain/MX Rate Limit Helpers ---
    def get_mx_records_cache_ttl(self):
        return self.get_domain_mx_limit('mx_records_cache_ttl')

    def get_mx_ip_cache_ttl(self):
        return self.get_domain_mx_limit('mx_ip_cache_ttl')

    def get_mx_preferences_cache_ttl(self):
        return self.get_domain_mx_limit('mx_preferences_cache_ttl')

    def get_reverse_dns_cache_ttl(self):
        return self.get_domain_mx_limit('reverse_dns_cache_ttl')

    def get_whois_cache_ttl(self):
        return self.get_domain_mx_limit('whois_cache_ttl')
    
    # --- Auth/Security Rate Limit Helpers ---
    def get_spf_max_lookups(self):
        return self.get_auth_security_limit('spf_max_lookups')

    def get_spf_cache_ttl(self):
        return self.get_cache_limit('spf_cache_ttl')

    def get_dkim_cache_ttl(self):
        return self.get_cache_limit('dkim_cache_ttl')

    def get_dmarc_cache_ttl(self):
        return self.get_cache_limit('dmarc_cache_ttl')

    def get_smtp_port25_conn_interval(self):
        return self.get_auth_security_limit('smtp_port25_conn_interval')

    def get_smtp_port587_conn_interval(self):
        return self.get_auth_security_limit('smtp_port587_conn_interval')

    def get_smtp_banner_grab_interval(self):
        return self.get_auth_security_limit('smtp_banner_grab_interval')

    def get_dnssec_cache_ttl(self):
        return self.get_cache_limit('dnssec_cache_ttl')

    def get_tls_rpt_cache_ttl(self):
        return self.get_cache_limit('tls_rpt_cache_ttl')

    def get_mta_sts_fetch_interval(self):
        return self.get_auth_security_limit('mta_sts_fetch_interval')

    def get_tls_cipher_probe_interval(self):
        return self.get_auth_security_limit('tls_cipher_interval')

    def get_rbl_check_interval(self):
        return self.get_auth_security_limit('rbl_check_interval')

    def record_usage(self, category, resource_id):
        """
        Record usage of a rate-limited resource
        """
        from src.managers.cache import cache_manager, CacheKeys
        key = f"rate_limit:{category}:{resource_id}"  # Simplified key format
        count = cache_manager.get(key) or 0
        count += 1
        cache_manager.set(key, count, ttl=60)
        
        # Debug log
        logger.debug(f"Recorded usage: {category}.{resource_id} = {count}")
        return count
    
    def get_usage_count(self, category, resource_id):
        """Get current usage count for a rate-limited resource"""
        from src.managers.cache import cache_manager
        key = f"rate_limit:{category}:{resource_id}"  # Simplified key format
        count = cache_manager.get(key) or 0
        return count
    
    def check_rate_limit(self, category, resource_id, limit_name):
        """
        Check if a rate limit has been reached
        
        Args:
            category: The rate limit category (e.g., 'smtp', 'dom_mx')
            resource_id: The resource being limited (e.g., domain name)
            limit_name: The specific limit to check
            
        Returns:
            Tuple of (is_limit_exceeded, limit_info_dict)
        """
        current_count = self.get_usage_count(category, resource_id)
        limit_value = None
        period = "60 seconds"  # Default period assumption
        
        try:
            if category == 'smtp':
                limit_value = self.get_smtp_limit(limit_name)
                
                # Set appropriate period description based on limit name
                if limit_name == 'max_connections_per_minute':
                    period = "minute"
                elif limit_name == 'max_connections_per_domain':
                    period = "minute per domain"
                elif 'timeout' in limit_name:
                    period = "connection"
                    
                # Validate limit value for critical settings
                if limit_name == 'max_connections_per_domain' and (limit_value is None or limit_value <= 0):
                    logger.warning(f"Invalid {limit_name} value: {limit_value}, using default of 5")
                    limit_value = 5  # Use a sensible default
            
            elif category == 'dom_mx':
                limit_value = self.get_domain_mx_limit(limit_name)
                period = "domain operation"
            elif category == 'auth_security':
                limit_value = self.get_auth_security_limit(limit_name)
                period = "security check"
            elif category == 'additional':
                limit_value = self.get_additional_protocol_limit(limit_name)
                period = "protocol check"
            elif category == 'cache':
                limit_value = self.get_cache_limit(limit_name)
                period = "cache operation"
            elif category == 'dns':
                limit_value = self.get_dns_limit(limit_name)
                period = "DNS lookup"
            else:
                logger.error(f"Unknown rate limit category: {category}")
                return False, {'limit': 'unknown', 'current': current_count, 'period': 'unknown category'}
        except Exception as e:
            logger.error(f"Failed to get rate limit {category}.{limit_name}: {e}")
            if limit_name == 'max_connections_per_domain':
                # For this critical setting, use a default instead of failing
                limit_value = 5
                logger.warning(f"Using default value of {limit_value} for {limit_name}")
                return current_count >= limit_value, {'limit': limit_value, 'current': current_count, 'period': period}
            else:
                return False, {'limit': 'error', 'current': current_count, 'period': 'error condition', 'error': str(e)}
    
        # Ensure we have a valid limit value before comparison
        if limit_value is None or not isinstance(limit_value, (int, float)) or limit_value <= 0:
            logger.warning(f"Invalid limit value for {category}.{limit_name}: {limit_value}, allowing operation")
            return False, {'limit': 'unlimited', 'current': current_count, 'period': period}
        
        try:
            # Ensure integer comparison since rate_limit.value is INTEGER NOT NULL in database
            limit_value = int(limit_value)
            is_exceeded = int(current_count) >= limit_value
        except (ValueError, TypeError):
            logger.error(f"Type error comparing {current_count} with {limit_value}")
            is_exceeded = False
        
        # Always return a consistent dictionary format with all required keys
        limit_info = {
            'limit': limit_value,
            'current': current_count,
            'period': period,
            'name': limit_name
        }
        
        return is_exceeded, limit_info
    
    def is_near_limit(self, category, resource_id, limit_name, threshold_percent=80):
        """
        Check if usage is approaching the rate limit
        """
        current = self.get_usage_count(category, resource_id)
        limit_value = None
        try:
            if category == 'smtp':
                limit_value = self.get_smtp_limit(limit_name)
            elif category == 'dom_mx':
                limit_value = self.get_domain_mx_limit(limit_name)
            elif category == 'auth_security':
                limit_value = self.get_auth_security_limit(limit_name)
            elif category == 'additional':
                limit_value = self.get_additional_protocol_limit(limit_name)
            elif category == 'cache':
                limit_value = self.get_cache_limit(limit_name)
            elif category == 'dns':
                limit_value = self.get_dns_limit(limit_name)
        except Exception as e:
            logger.error(f"Failed to get rate limit {category}.{limit_name}: {e}")
            return False
        
        if not limit_value or limit_value <= 0:
            return False
            
        percent_used = (current / limit_value) * 100
        return percent_used >= threshold_percent

    # --- SMTP Block Duration Methods ---
    def get_timeout_block_duration(self):
        """Get block duration for SMTP timeouts in seconds"""
        try:
            return self.get_smtp_limit('timeout_block_duration')
        except KeyError:
            return 600  # 10 minutes default
    
    def get_rate_limit_block_duration(self):
        """Get block duration for rate limit violations in seconds"""
        try:
            return self.get_smtp_limit('rate_limit_block_duration')
        except KeyError:
            return 300  # 5 minutes default

    # Add new helper methods for the SMTP domain management cache settings
    def get_smtp_domain_stats_ttl(self):
        """Get cache TTL for SMTP domain statistics"""
        try:
            return self.get_cache_limit('smtp_domain_stats_ttl')
        except KeyError:
            return 3600  # 1 hour default
    
    def get_smtp_attempt_history_ttl(self):
        """Get cache TTL for SMTP attempt history"""
        try:
            return self.get_cache_limit('smtp_attempt_history_ttl')
        except KeyError:
            return 86400  # 24 hours default
    
    def get_smtp_regional_settings_ttl(self):
        """Get cache TTL for SMTP regional settings"""
        try:
            return self.get_cache_limit('smtp_regional_settings_ttl')
        except KeyError:
            return 604800  # 7 days default

    def get_auth_security_limit(self, limit_name: str) -> Any:
        """Get auth/security rate limit"""
        try:
            result = sync_db.fetchval(
                "SELECT value FROM rate_limit WHERE category = 'auth_security' AND name = $1 AND enabled = TRUE",
                limit_name
            )
            return result or 0
        except Exception as e:
            logger.warning(f"Failed to get auth/security limit {limit_name}: {e}")
            return 0

    def get_cache_limit(self, limit_name: str) -> int:
        """Get cache TTL limit"""
        try:
            result = sync_db.fetchval(
                "SELECT value FROM rate_limit WHERE category = 'cache' AND name = $1 AND enabled = TRUE",
                limit_name
            )
            return int(result) if result else 3600
        except Exception as e:
            logger.warning(f"Failed to get cache limit {limit_name}: {e}")
            return 3600

    def _check_domain_rate_limit(self, domain: str, port: int, trace_id: Optional[str] = None) -> bool:
        """Check if we can connect to this domain based on rate limits"""
        # Bypass rate limiting in test mode
        if self.test_mode:
            return True
        
        global _domain_last_connection
    
        with _rate_limiter_lock:
            current_time = time.time()
            
            # Check if domain has a recent connection
            if domain in _domain_last_connection:
                last_time = _domain_last_connection[domain]
                time_diff = current_time - last_time
                
                # Get the minimum interval between connections to the same domain
                if port == 25:
                    min_interval = self.get_smtp_port25_conn_interval()
                elif port in (587, 465):
                    min_interval = self.get_smtp_port587_conn_interval()
                else:
                    min_interval = self.get_smtp_port25_conn_interval()  # Default
                
                if time_diff < min_interval:
                    logger.warning(f"[{trace_id}] Rate limit exceeded for {domain}. "
                                 f"Min interval: {min_interval}s, Time since last: {time_diff:.2f}s, "
                                 f"Need to wait: {min_interval - time_diff:.2f}s more")
                    return False
            
            # Update last connection time
            _domain_last_connection[domain] = current_time
            
            # Use the rate limit manager's check_rate_limit method
            try:
                is_exceeded, limit_info = self.check_rate_limit(
                    'smtp', domain, 'max_connections_per_domain')
            except Exception as e:
                logger.warning(f"[{trace_id}] Error checking rate limit for {domain}: {e}")
                return True  # Be conservative and allow the connection on error
            
            if is_exceeded:
                # Extract info from the limit_info dictionary with appropriate defaults
                limit_value = limit_info.get('limit', 'unknown')
                period = limit_info.get('period', 'unknown period')
                current_count = limit_info.get('current', 0)
                
                logger.warning(f"[{trace_id}] Global rate limit exceeded for {domain}. "
                             f"Current: {current_count}/{limit_value} connections per {period}")
                
                # Add domain to temporary blocklist when rate limited
                self._add_to_temporary_blocklist(
                    domain, 
                    f"Rate limit exceeded: {current_count}/{limit_value} per {period}", 
                    trace_id
                )
                return False
            
            return True

    def _add_to_temporary_blocklist(self, domain: str, reason: str, trace_id: Optional[str] = None):
        """
        Add a domain to a temporary blocklist due to rate limiting.
        This is a stub implementation; you may want to integrate with your cache or blocklist system.
        """
        logger.warning(f"[{trace_id}] Domain '{domain}' temporarily blocklisted. Reason: {reason}")
        # Example: store in memory or cache for a period, or integrate with a real blocklist system.
        # For now, this is just a log.

# Create a singleton instance for external use
rate_limit_manager = RateLimitManager()