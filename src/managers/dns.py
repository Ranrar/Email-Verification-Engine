"""
Email Verification Engine
===================================
DNS Manager for EVE:
This module handles all DNS settings for different EVE components.
It uses the dns_settings table in the PostgreSQL database.
"""


import traceback
import dns.resolver
import threading
import time
from typing import Any, Dict, List
from src.managers.executor import ThreadPoolexecutor
from src.helpers.dbh import sync_db
from src.managers.log import Axe
from src.managers.cache import cache_manager, CacheKeys
from src.managers.rate_limit import rate_limit_manager
from src.engine.functions.statistics import DNSServerStats

# maby add a warmup to populate the dns servers on cold start

# Set up logging
logger = Axe()

class DNSManager:
    """
    Central manager for DNS settings across the EVE system.
    Uses a singleton pattern to ensure only one instance exists.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DNSManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        # Only basic property initialization here
        if self._initialized:
            return
            
        # Mark initialized but defer actual initialization to Initialization.py
        self._initialized = True
        self.dns_settings = None
        self._prefetch_executor = None
        self._dns_stats = DNSServerStats()
        
        # Log basic instantiation but not full initialization
        logger.debug("DNS manager instance created, awaiting proper initialization")
    
    def initialize(self, prefetch_executor_workers=2) -> 'DNSManager':
        """Initialize the DNS manager with proper settings"""
        # Only run initialization if not already done
        if self._prefetch_executor is not None:
            logger.debug("DNS manager already initialized")
            return self
        
        # Create thread pool for prefetching
        self._prefetch_executor = ThreadPoolexecutor(max_workers=prefetch_executor_workers)
        
        # No initial loading - will load on demand
        logger.info("DNS settings manager initialized with lazy loading")
        return self
    
    def _load_dns_settings(self):
        """Load DNS settings from database."""
        settings = {}
        try:
            # Try to get from dns_settings table first (dedicated table)
            rows = sync_db.fetch("SELECT name, value, is_time, description FROM dns_settings")
            if rows:
                for row in rows:
                    settings[row['name']] = {
                        'value': row['value'],
                        'is_time': row['is_time'],
                        'description': row['description']
                    }
                logger.info(f"Loaded {len(settings)} DNS settings")
                return settings
                
            # Fall back to app_settings if dns_settings is empty
            rows = sync_db.fetch("""
                SELECT name, value FROM app_settings 
                WHERE category='dns'
            """)
            for row in rows:
                settings[row['name']] = {
                    'value': row['value'],
                    'is_time': row['name'] in ('timeout', 'stats_retention_days'),
                    'description': None
                }
            logger.info(f"Loaded {len(settings)} DNS settings from app_settings")
        except Exception as e:
            logger.error(f"Failed to load DNS settings: {e}")
        return settings
    
    def reload_settings(self):
        """Reload DNS settings from database"""
        self.dns_settings = None
        logger.info("DNS settings marked for reload")
        
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all DNS settings"""
        if self.dns_settings is None:
            self.dns_settings = self._load_dns_settings()
        return self.dns_settings
    
    def get_setting(self, setting_name: str) -> Any:
        """Get a specific DNS setting"""
        if self.dns_settings is None:
            self.dns_settings = self._load_dns_settings()
    
        # If setting exists, return its value
        if setting_name in self.dns_settings:
            return self.dns_settings[setting_name]['value']
        
        # If it's not found, raise an error
        logger.error(f"DNS setting '{setting_name}' not found in database")
        raise KeyError(f"DNS setting '{setting_name}' not found in database")
    
    def update_setting(self, setting_name: str, value: Any) -> bool:
        """Update a DNS setting in the database"""
        try:
            # Get current setting to keep is_time flag consistent
            current_settings = self.dns_settings or self._load_dns_settings()
            is_time = False
            
            if setting_name in current_settings:
                is_time = current_settings[setting_name]['is_time']
            else:
                # Fallback logic for new settings
                is_time = setting_name in ('timeout', 'stats_retention_days')
            
            # Convert value to string for storage
            string_value = str(value)
            
            # Update the setting
            query = "UPDATE dns_settings SET value = $1 WHERE name = $2"
            sync_db.execute(query, string_value, setting_name)
            
            # Mark for reload
            self.reload_settings()
            
            logger.info(f"Updated DNS setting {setting_name} = {value}")
            return True
        except Exception as e:
            logger.error(f"Failed to update DNS setting {setting_name}: {str(e)}")
            return False
    
    def add_setting(self, setting_name: str, value: Any, is_time: bool, description: str = "") -> bool:
        """Add a new DNS setting to the database"""
        try:
            # Convert value to string for storage
            string_value = str(value)
            
            # Insert the new setting
            query = """
                INSERT INTO dns_settings (name, value, is_time, description)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (name) DO UPDATE
                SET value = $2, is_time = $3, description = $4
            """
            sync_db.execute(query, setting_name, string_value, is_time, description)
            
            # Mark for reload
            self.reload_settings()
            
            logger.info(f"Added DNS setting {setting_name} = {value}")
            return True
        except Exception as e:
            logger.error(f"Failed to add DNS setting {setting_name}: {str(e)}")
            return False
    
    def verify_database_connection(self):
        """Verify database connection and reset cached settings"""
        try:
            # Reset cached settings
            self.dns_settings = None
            
            # Test database connection with a simple query
            version = sync_db.fetchval("SELECT version()")
            
            # Count DNS settings
            query = "SELECT COUNT(*) as setting_count FROM dns_settings"
            result = sync_db.fetchrow(query)
            
            if result:
                setting_count = result['setting_count']
                logger.info(f"DNS manager: Database connection verified. Found {setting_count} DNS settings. PostgreSQL version: {version}")
                return True
            else:
                logger.error("DNS manager: Database connection failed or no DNS settings found")
                return False
                
        except Exception as e:
            logger.error(f"DNS manager: Database verification failed: {str(e)}")
            
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    # Helper methods for common DNS settings
    
    def get_nameservers_list(self) -> List[str]:
        """Get nameservers as a list of IP address strings"""
        try:
            # Try to get nameservers from the dedicated table first
            nameservers = self.get_nameservers_from_db()
            
            if nameservers:
                # Extract the IP addresses
                return [ns['ip_address'] for ns in nameservers]
            
            # Fallback to the old method if the table is empty
            nameservers_str = self.get_setting('nameservers')
            return [ns.strip() for ns in nameservers_str.split(',') if ns.strip()]
        except Exception as e:
            logger.error(f"Failed to get nameserver list: {e}")
            # Return some public DNS servers as a last resort fallback
            logger.warning("Using fallback DNS servers (Cloudflare and Google)")
            return ['1.1.1.1', '8.8.8.8']
    
    def get_timeout(self) -> float:
        """Get DNS timeout in seconds"""
        value = self._get_setting_with_fallback('timeout', 5.0)
        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f"Invalid timeout value: {value}, using default of 5.0 seconds")
            return 5.0

    def get_selection_strategy(self) -> str:
        """Get nameserver selection strategy"""
        return self._get_setting_with_fallback('selection_strategy', '2')

    def get_collect_stats(self) -> bool:
        """Get whether to collect DNS server performance statistics"""
        value = self._get_setting_with_fallback('collect_stats', '1')
        return str(value).lower() in ('1', 'true', 'yes', 'on')

    def get_stats_retention_days(self) -> int:
        """Get number of days to retain DNS server statistics"""
        value = self._get_setting_with_fallback('stats_retention_days', 30)
        try:
            return int(value)
        except (ValueError, TypeError):
            return 30

    def get_max_attempts(self) -> int:
        """Get maximum number of DNS resolution attempts"""
        value = self._get_setting_with_fallback('max_attempts', 3)
        try:
            return int(value)
        except (ValueError, TypeError):
            return 3

    def get_max_queries_per_minute(self) -> int:
        """Get maximum DNS queries allowed per minute total"""
        return int(self.get_setting('max_queries_per_minute'))

    def get_max_queries_per_domain(self) -> int:
        """Get maximum DNS queries allowed per minute for a specific domain"""
        return int(self.get_setting('max_queries_per_domain'))
    
    def get_use_edns(self) -> bool:
        """Get whether to use EDNS extensions for DNS queries"""
        return bool(self.get_setting('use_edns'))
    
    def get_use_tcp(self) -> bool:
        """Get whether to force TCP for DNS queries instead of UDP"""
        return bool(self.get_setting('use_tcp'))
    
    def get_use_dnssec(self) -> bool:
        """Get whether to enable DNSSEC validation for DNS queries"""
        return bool(self.get_setting('use_dnssec'))
    
    def get_prefer_ipv6(self) -> bool:
        """Get whether to prefer IPv6 addresses when available"""
        return bool(self.get_setting('prefer_ipv6'))

    # Prefetch methods for DNS records

    def prefetch_related_records(self, domain):
        """
        Pre-fetch related DNS records that will likely be needed soon.
        This optimizes subsequent queries by having data already in cache.
        
        Args:
            domain: Domain to prefetch records for
        """
        
        
        def _async_prefetch():
            try:
                # Don't prefetch if we're near rate limits
                
                if rate_limit_manager.is_near_limit('dom_mx', domain, 'max_queries_per_domain'):
                    logger.debug(f"Skipping prefetch for {domain} due to rate limit")
                    return
                    
                # Only prefetch if not already in cache
                mx_key = CacheKeys.mx_records(domain)
                if not cache_manager.get(mx_key):
                    # First get MX records
                    self._prefetch_mx_records(domain)
                    
                # Now try to prefetch SPF, DKIM, DMARC records
                self._prefetch_auth_records(domain)
                    
            except Exception as e:
                logger.error(f"Error during DNS prefetching for {domain}: {e}")
        
        # Ensure the prefetch executor is initialized
        if self._prefetch_executor is None:
            self._prefetch_executor = ThreadPoolexecutor(max_workers=2)
        # Run the prefetch asynchronously
        self._prefetch_executor.submit(_async_prefetch)
        
    def _prefetch_mx_records(self, domain):
        """Prefetch MX records for a domain"""
        try:
            # Check if we already have this in cache
            key = CacheKeys.mx_records(domain)
            if cache_manager.get(key):
                return
                
            # Get MX records using our configured resolver
            answers = self.resolve(domain, 'MX')
            
            # Format the result
            mx_records = []
            for rdata in answers:
                # rdata.to_text() returns "preference exchange"
                parts = rdata.to_text().split()
                if len(parts) == 2:
                    preference, exchange = parts
                    mx_records.append({
                        'preference': int(preference),
                        'exchange': exchange.rstrip('.')
                    })
                
            # Cache the result
            # Use a default TTL value for MX records
            default_ttl = 3600  # Set TTL to 1 hour (3600 seconds)
            cache_manager.set_with_ttl(key, mx_records, default_ttl)
                
            logger.debug(f"Prefetched MX records for {domain}")
            
            # For each MX record, also prefetch its A records
            for mx in mx_records[:2]:  # Just do the top 2 priority servers
                mx_host = mx['exchange']
                self._prefetch_a_records(mx_host)
                
        except Exception as e:
            logger.debug(f"MX record prefetch failed for {domain}: {e}")

    def _prefetch_a_records(self, hostname):
        """Prefetch A records for a hostname"""
       
        
        try:
            # Check if we already have this in cache
            key = CacheKeys.dns_records_key('A', hostname)
            if cache_manager.get(key):
                return
                
            # Get A records
            
            answers = dns.resolver.resolve(hostname, 'A')
            
            # Format the result
            a_records = [rdata.to_text() for rdata in answers]
                
            # Cache the result
            ttl = CacheKeys.get_ttl_from_db('DNS_RECORDS')
            if ttl:
                cache_manager.set_with_ttl(key, a_records, ttl)
            else:
                cache_manager.set(key, a_records)
                
            logger.debug(f"Prefetched A records for {hostname}")
                
        except Exception as e:
            logger.debug(f"A record prefetch failed for {hostname}: {e}")

    def _prefetch_auth_records(self, domain):
        """Prefetch authentication records (SPF, DKIM, DMARC)"""
        
        
        # Prefetch SPF (usually in TXT record at domain)
        try:
            spf_key = CacheKeys.dns_records_key('SPF', domain)
            if not cache_manager.get(spf_key):
               
                answers = dns.resolver.resolve(domain, 'TXT')
                
                # Look for SPF records
                spf_records = []
                for rdata in answers:
                    txt = rdata.to_text()
                    if 'v=spf1' in txt:
                        spf_records.append(txt)
                        
                if spf_records:
                    ttl = CacheKeys.get_ttl_from_db('DNS_RECORDS')
                    if ttl:
                        cache_manager.set_with_ttl(spf_key, spf_records, ttl)
                    else:
                        cache_manager.set(spf_key, spf_records)
                    logger.debug(f"Prefetched SPF record for {domain}")
        except Exception as e:
            logger.debug(f"SPF prefetch failed for {domain}: {e}")
            
        # Prefetch DMARC (usually at _dmarc.domain)
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_key = CacheKeys.dns_records_key('DMARC', domain)
            if not cache_manager.get(dmarc_key):

                try:
                    answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                    
                    # Look for DMARC records
                    dmarc_records = []
                    for rdata in answers:
                        txt = rdata.to_text()
                        if 'v=DMARC1' in txt:
                            dmarc_records.append(txt)
                            
                    if dmarc_records:
                        ttl = CacheKeys.get_ttl_from_db('DNS_RECORDS')
                        if ttl:
                            cache_manager.set_with_ttl(dmarc_key, dmarc_records, ttl)
                        else:
                            cache_manager.set(dmarc_key, dmarc_records)
                        logger.debug(f"Prefetched DMARC record for {domain}")
                except dns.resolver.NXDOMAIN:
                    # No DMARC record - cache this fact too
                    ttl = CacheKeys.get_ttl_from_db('DNS_RECORDS')
                    if ttl:
                        cache_manager.set_with_ttl(dmarc_key, [], ttl)
                    else:
                        cache_manager.set(dmarc_key, [])
        except Exception as e:
            logger.debug(f"DMARC prefetch failed for {domain}: {e}")

    def get_nameservers_from_db(self, include_ipv6=None, filter_provider=None, active_only=True) -> List[Dict[str, Any]]:
        """
        Get nameservers from the dns_nameservers table
    
        Args:
            include_ipv6: If True, include IPv6 servers. If False, exclude them. If None, use prefer_ipv6 setting.
            filter_provider: Optional provider name to filter by
            active_only: If True, only return active nameservers
        
        Returns:
            List of nameserver dictionaries with all their properties
        """
        try:
            # Determine IPv6 preference if not specified
            if include_ipv6 is None:
                include_ipv6 = self.get_prefer_ipv6()
        
            # Build query conditions
            conditions = []
            params = []
        
            if active_only:
                conditions.append("is_active = TRUE")
            
            if not include_ipv6:
                conditions.append("version = 'IPv4'")
            
            if filter_provider:
                conditions.append("provider = $" + str(len(params) + 1))
                params.append(filter_provider)
            
            # Build the full query
            query = "SELECT * FROM dns_nameservers"
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
            query += " ORDER BY priority, id"
        
            # Execute query
            nameservers = sync_db.fetch(query, *params)
            logger.debug(f"Retrieved {len(nameservers)} nameservers from database")
        
            return nameservers
        except Exception as e:
            logger.error(f"Failed to retrieve nameservers from database: {e}")
            return []
    
    # Add shutdown method to clean up resources
    def shutdown(self):
        """Shutdown the DNS manager and clean up resources"""
        if hasattr(self, '_prefetch_executor') and self._prefetch_executor:
            logger.info("Shutting down DNS prefetch executor")
            self._prefetch_executor.shutdown(wait=True)
            self._prefetch_executor = None
            
        # Close any other resources
        self._clean_up_statistics()
        logger.info("DNS manager shutdown complete")

    def _clean_up_statistics(self):
        """Clean up old statistics records"""
        try:
            retention_days = self.get_stats_retention_days()
            if retention_days > 0:
                self._dns_stats.clean_up_old_stats(retention_days)
        except Exception as e:
            logger.error(f"Failed to clean up DNS statistics: {e}")

    def create_resolver(self) -> dns.resolver.Resolver:
        """
        Create and configure a DNS resolver with current settings
        
        Returns:
            Configured dns.resolver.Resolver instance
        """
        resolver = dns.resolver.Resolver()
        
        try:
            # Apply nameservers from database
            resolver.nameservers = self.get_nameservers_list()
            
            # Apply timeout setting
            try:
                resolver.timeout = float(self.get_timeout())
            except (ValueError, KeyError):
                logger.warning("Invalid timeout value, using default of 5 seconds")
                resolver.timeout = 5.0
                
            # Apply EDNS settings if supported
            use_edns = self.get_use_edns()
            if use_edns:
                try:
                    # Set EDNS payload size if specified
                    edns_payload = int(self.get_setting('edns_payload_size'))
                except (ValueError, KeyError):
                    # Use default payload size
                    edns_payload = 1232
                # Store EDNS settings for use during resolution
                self._edns_enabled = True
                self._edns_payload = edns_payload
            else:
                self._edns_enabled = False
                self._edns_payload = None
                    
            # Store TCP fallback setting for use during resolution
            try:
                self._force_tcp = self.get_use_tcp()
            except KeyError:
                # Try alternative key name
                try:
                    self._force_tcp = bool(self.get_setting('fallback_to_tcp'))
                except KeyError:
                    self._force_tcp = False
            
            # Apply DNSSEC validation if supported
            try:
                if self.get_use_dnssec():
                    logger.warning("DNSSEC validation requested, but not supported by dns.resolver.Resolver")
            except (KeyError, AttributeError):
                # Not all resolver implementations support this
                pass
                
            logger.debug(f"Created DNS resolver with {len(resolver.nameservers)} nameservers, " +
                        f"timeout={resolver.timeout}s, EDNS={getattr(resolver, 'use_edns', False)}")
            
            return resolver
        except Exception as e:
            logger.error(f"Error configuring resolver, using defaults: {e}")
            return dns.resolver.Resolver()  # Return default resolver as fallback

    def select_nameservers(self, count=2) -> List[str]:
        """
        Select nameservers based on the configured selection strategy
    
        Args:
            count: Number of nameservers to select
        
        Returns:
            List of selected nameserver IP addresses
        """
        try:
            # Get all active nameservers
            nameservers = self.get_nameservers_from_db()
            if not nameservers:
                return ['1.1.1.1', '8.8.8.8']  # Fallback

            selected = []  # Ensure 'selected' is always defined
                
            # Get selection strategy
            try:
                strategy = self.get_selection_strategy()
            except KeyError:
                strategy = '2'  # Default to round-robin
                
            # Convert to integer if it's a string
            if isinstance(strategy, str):
                try:
                    strategy = int(strategy)
                except ValueError:
                    strategy = 2  # Default to round-robin
        
            # Apply the selected strategy
            if strategy == 1:
                # Random selection
                import random
                selected = random.sample(nameservers, min(count, len(nameservers)))
                
            elif strategy == 3 and self.get_collect_stats():
                # Best performer strategy using DNSServerStats class
                try:
                    # Get best performing nameservers using the stats class
                    best_nameservers = self._dns_stats.get_best_nameservers(count)
                    
                    if best_nameservers and len(best_nameservers) >= count:
                        # Find the corresponding full nameserver objects for additional info if needed
                        ip_to_ns = {ns['ip_address']: ns for ns in nameservers}
                        selected_ns = []
                        
                        for ip in best_nameservers:
                            if ip in ip_to_ns:
                                selected_ns.append(ip_to_ns[ip])
                            else:
                                # IP from stats not found in current nameservers
                                # This could happen if a nameserver was recently deactivated
                                logger.debug(f"Nameserver {ip} found in stats but not in active nameservers")
                        
                        # If we have enough matches, use them
                        if len(selected_ns) >= count:
                            selected = selected_ns
                        else:
                            # Fill remaining slots with other nameservers based on priority
                            selected_ips = {ns['ip_address'] for ns in selected_ns}
                            remaining = [ns for ns in nameservers if ns['ip_address'] not in selected_ips]
                            selected = selected_ns + remaining[:count - len(selected_ns)]
                    else:
                        # Fall back to round-robin if not enough stats available
                        logger.debug("Insufficient nameserver performance stats, using round-robin selection")
                        strategy = 2
                except Exception as e:
                    logger.error(f"Error in best performer selection: {e}")
                    strategy = 2  # Fall back to round-robin
        
            # Default: Round-robin or fallback from other strategies
            if strategy == 2 or strategy not in (1, 3) or not selected:
                # Simple round-robin based on priority
                selected = nameservers[:count]
                
            # Extract IP addresses
            return [ns['ip_address'] for ns in selected]
            
        except Exception as e:
            logger.error(f"Error in nameserver selection: {e}")
            return ['1.1.1.1', '8.8.8.8']  # Fallback to reliable public DNS

    def record_dns_query_stats(self, nameserver, query_type, status, response_time=None, error_message=None):
        """Record statistics about DNS query performance and reliability"""
        try:
            if not self.get_collect_stats():
                return
                
            # Use the statistics module to record stats
            self._dns_stats.record_query_stats(
                nameserver, query_type, status, response_time, error_message
            )
        except Exception as e:
            logger.error(f"Failed to record DNS query stats: {e}")

    def resolve(self, hostname, record_type):
        """
        Resolve DNS records with tracking, stats, and proper configuration
    
        Args:
            hostname: Hostname to resolve
            record_type: DNS record type (A, MX, TXT, etc.)
        
        Returns:
            DNS answer object or None if resolution failed
        """
        # Create a resolver with current settings
        resolver = self.create_resolver()
        start_time = time.time()
        nameserver_used = resolver.nameservers[0] if resolver.nameservers else "unknown"
        
        try:
            # Perform the resolution, using TCP if configured
            use_tcp = getattr(self, '_force_tcp', False)
            # Use EDNS options if enabled
            if getattr(self, '_edns_enabled', False):
                edns_payload = getattr(self, '_edns_payload', 1232)
                answers = resolver.resolve(
                    hostname, record_type, tcp=use_tcp
                )
            else:
                answers = resolver.resolve(hostname, record_type, tcp=use_tcp)
            
            # Record successful query stats
            elapsed_ms = (time.time() - start_time) * 1000
            self.record_dns_query_stats(
                nameserver_used,
                record_type,
                'success',
                elapsed_ms
            )
            
            return answers
        except Exception as e:
            # Record failed query stats
            elapsed_ms = (time.time() - start_time) * 1000
            self.record_dns_query_stats(
                nameserver_used,
                record_type,
                'failure',
                None,
                str(e)
            )
            
            # Propagate the exception
            raise
    
    # Add this helper method for consistent error handling
    def _get_setting_with_fallback(self, setting_name, default_value=None, log_level="warning"):
        """
        Get a setting with consistent error handling and fallback
    
        Args:
            setting_name: Name of setting to retrieve
            default_value: Value to return if setting is missing
            log_level: Logging level for missing settings ("error", "warning", "debug")
    
        Returns:
            Setting value or default_value
        """
        try:
            if self.dns_settings is None:
                self.dns_settings = self._load_dns_settings()
            
            if setting_name in self.dns_settings:
                return self.dns_settings[setting_name]['value']
            
            # Setting not found
            message = f"DNS setting '{setting_name}' not found in database, using default: {default_value}"
            if log_level == "error":
                logger.error(message)
            elif log_level == "warning":
                logger.warning(message)
            else:
                logger.debug(message)
            
            if default_value is None:
                raise KeyError(f"DNS setting '{setting_name}' not found and no default provided")
            return default_value
            
        except Exception as e:
            if default_value is None:
                logger.error(f"Error retrieving setting '{setting_name}': {e}")
                raise
            logger.warning(f"Error retrieving setting '{setting_name}', using default: {default_value}")
            return default_value
