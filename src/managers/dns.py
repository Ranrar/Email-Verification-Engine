"""
Email Verification Engine
===================================
DNS Manager:
Central DNS management for EVE components.
Handles settings, nameserver selection, and resolution.
"""

import traceback
import threading
import time
from typing import Any, Dict, List
import dns.resolver

from src.managers.executor import ThreadPoolexecutor
from src.helpers.dbh import sync_db
from src.managers.log import Axe
from src.managers.cache import cache_manager, CacheKeys
from src.managers.rate_limit import rate_limit_manager
from src.engine.functions.statistics import DNSServerStats
from src.helpers.ipv4_resolver import IPv4Resolver
from src.helpers.ipv6_resolver import IPv6Resolver

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
        
        # Create resolvers
        self.ipv4_resolver = IPv4Resolver()
        self.ipv6_resolver = IPv6Resolver()
        
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
    
    # Helper methods for common DNS settings
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
    
    def get_prefer_ipv6(self) -> bool:
        """Get whether to prefer IPv6 addresses when available"""
        try:
            prefer_setting = bool(self.get_setting('prefer_ipv6'))
            if prefer_setting:
                # Only return True if IPv6 is actually available
                return self.ipv6_resolver.is_available()
            return False
        except Exception:
            return False

    def get_use_edns(self) -> bool:
        """Get whether to use EDNS extensions for DNS queries"""
        return bool(self._get_setting_with_fallback('use_edns', False))
    
    def get_use_tcp(self) -> bool:
        """Get whether to force TCP for DNS queries instead of UDP"""
        return bool(self._get_setting_with_fallback('use_tcp', 
                 self._get_setting_with_fallback('fallback_to_tcp', False, log_level="debug"), 
                 log_level="debug"))
        
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
    
    def resolve(self, hostname: str, record_type: str, force_ipv4: bool = False, force_ipv6: bool = False):
        """
        Resolve DNS records with appropriate IPv4/IPv6 handling
        
        Args:
            hostname: Hostname to resolve
            record_type: DNS record type (A, MX, TXT, etc.)
            force_ipv4: Force using IPv4 resolver
            force_ipv6: Force using IPv6 resolver
            
        Returns:
            DNS answer object
        """
        # Determine which resolver to use
        use_ipv6 = False
        if force_ipv6:
            if not self.ipv6_resolver.is_available():
                raise ValueError("IPv6 resolution requested but IPv6 is not available")
            use_ipv6 = True
        elif not force_ipv4:
            # Check IPv6 preference if not explicitly using IPv4
            use_ipv6 = self.get_prefer_ipv6()
        
        # Get configured nameservers
        selected_nameservers = self.select_nameservers(count=2)
        nameserver_used = selected_nameservers[0] if selected_nameservers else None
        
        start_time = time.time()
        try:
            if use_ipv6:
                # Use IPv6 resolver
                answers = self.ipv6_resolver.resolve(
                    hostname, 
                    record_type,
                    nameservers=selected_nameservers,
                    timeout=self.get_timeout(),
                    use_tcp=self.get_use_tcp(),
                    use_edns=self.get_use_edns()
                )
            else:
                # Use IPv4 resolver
                answers = self.ipv4_resolver.resolve(
                    hostname, 
                    record_type,
                    nameservers=selected_nameservers,
                    timeout=self.get_timeout(),
                    use_tcp=self.get_use_tcp(),
                    use_edns=self.get_use_edns()
                )
                
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
    
    def select_nameservers(self, count=2) -> List[str]:
        """
        Select nameservers based on the configured selection strategy
    
        Args:
            count: Number of nameservers to select
        
        Returns:
            List of selected nameserver IP addresses
        """
        try:
            # Get IPv6 preference - this now checks availability too
            use_ipv6 = self.get_prefer_ipv6()
            
            # Get appropriate nameservers
            nameservers = self.get_nameservers_from_db(include_ipv6=use_ipv6)
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
                best_nameservers = self._dns_stats.get_best_nameservers(count)
                
                if best_nameservers and len(best_nameservers) >= count:
                    # Find the corresponding full nameserver objects for additional info if needed
                    ip_to_ns = {ns['ip_address']: ns for ns in nameservers}
                    selected_ns = []
                    
                    for ip in best_nameservers:
                        if ip in ip_to_ns:
                            selected_ns.append(ip_to_ns[ip])
                        else:
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
    
    # Prefetch methods and other methods would go here
    # [Additional prefetch methods, cleanup methods, etc. from the original file]