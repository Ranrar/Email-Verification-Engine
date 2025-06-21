"""
Email Verification Engine
===================================
Port Manager:
This module handles all port configurations for different EVE components.
It uses the consolidated ports table in the PostgreSQL database.
"""

import traceback
import threading
import time
from typing import List, Dict, Any, Optional
from src.helpers.dbh import sync_db
from src.managers.log import get_logger

logger = get_logger()

class Port:
    """Port record with attributes from the database"""
    def __init__(self, port: int, category: str, name: str, priority: int, security: str, protocol: str, enabled: bool, description: str):
        self.port = port
        self.category = category
        self.name = name
        self.priority = priority
        self.security = security
        self.protocol = protocol
        self.enabled = enabled
        self.description = description
    
    @property
    def uses_ssl(self) -> bool:
        """Determine if this port uses SSL/TLS by default"""
        return bool(self.security) and "SSL/TLS" in self.security
    
    @property
    def supports_starttls(self) -> bool:
        """Determine if this port supports STARTTLS"""
        return bool(self.security) and "STARTTLS" in self.security


class PortManager:
    """
    Central manager for port configurations across the EVE system.
    Uses a singleton pattern to ensure only one instance exists.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(PortManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        
        # Initialize category-specific port caches
        self.smtp_ports = None
        self.dns_ports = None
        self.auth_ports = None
        self.mail_ports = None
        
        # Add time tracking for cache freshness
        self.last_refresh = {}
        self.cache_ttl = 300  # 5 minutes
        
        # No initial loading - will load on demand
        logger.debug("Port manager instance created, awaiting proper initialization")

    def initialize(self) -> bool:
        """Load ports from database"""
        if self._initialized:
            return True
        
        try:
            # Query for new schema
            sql = """
            SELECT 
                port, category, name, priority, security, 
                protocol, enabled, description 
            FROM ports 
            ORDER BY category, priority
            """
            
            results = sync_db.fetch(sql)
            if not results:
                logger.error("No ports found in database")
                return False
                
            # Process results
            ports_dict = {}
            categories_dict = {}
            
            for row in results:
                # Create Port object
                port_obj = Port(
                    port=int(row['port']),
                    category=row['category'],
                    name=row['name'],
                    priority=int(row['priority']),
                    security=row['security'],
                    protocol=row['protocol'],
                    enabled=row['enabled'],
                    description=row['description']
                )
                
                # Add to ports dictionary
                ports_dict[port_obj.port] = port_obj
                
                # Add to categories dictionary
                if port_obj.category not in categories_dict:
                    categories_dict[port_obj.category] = []
                categories_dict[port_obj.category].append(port_obj)
            
            self.smtp_ports = ports_dict.get('smtp')
            self.dns_ports = ports_dict.get('dns')
            self.auth_ports = ports_dict.get('auth')
            self.mail_ports = ports_dict.get('mail')
            self._initialized = True
            
            port_count = len(ports_dict)
            category_count = len(categories_dict)
            logger.info(f"Port manager initialized with {port_count} ports in {category_count} categories")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing port manager: {e}")
            return False

    def _should_reload(self, cache_name):
        """Check if cache should be reloaded based on TTL"""
        now = time.time()
        last_time = self.last_refresh.get(cache_name, 0)
        return (now - last_time) > self.cache_ttl
    
    def _load_smtp_ports(self):
        """Load SMTP ports from database"""
        if self.smtp_ports is not None and not self._should_reload('smtp_ports'):
            logger.debug("SMTP ports already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT port, priority, enabled, description 
                FROM ports 
                WHERE category = 'smtp' 
                ORDER BY priority
            """
            results = sync_db.fetch(query)
            
            self.smtp_ports = []
            for row in results:
                port_info = {
                    'port': int(row['port']),
                    'priority': int(row['priority']),
                    'enabled': row['enabled'],
                    'description': row['description']
                }
                self.smtp_ports.append(port_info)
                
            self.last_refresh['smtp_ports'] = time.time()
            logger.debug(f"Loaded {len(self.smtp_ports)} SMTP ports")
        except Exception as e:
            logger.error(f"Failed to load SMTP ports: {str(e)}")
            self.smtp_ports = []  # Initialize with empty list on error
            raise
    
    def _load_dns_ports(self):
        """Load DNS, WHOIS, and RDAP ports from database"""
        if self.dns_ports is not None and not self._should_reload('dns_ports'):
            logger.debug("DNS ports already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT port, priority, enabled, description, category
                FROM ports 
                WHERE category IN ('dns', 'whois', 'rdap') 
                ORDER BY priority
            """
            results = sync_db.fetch(query)
            
            self.dns_ports = []
            for row in results:
                port_info = {
                    'port': int(row['port']),
                    'priority': int(row['priority']),
                    'enabled': row['enabled'],
                    'description': row['description'],
                    'category': row['category']
                }
                self.dns_ports.append(port_info)
                
            self.last_refresh['dns_ports'] = time.time()
            logger.debug(f"Loaded {len(self.dns_ports)} DNS ports")
        except Exception as e:
            logger.error(f"Failed to load DNS ports: {str(e)}")
            self.dns_ports = []
            raise
    
    def _load_auth_ports(self):
        """Load authentication and security ports from database"""
        if self.auth_ports is not None and not self._should_reload('auth_ports'):
            logger.debug("Auth ports already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT port, priority, enabled, description 
                FROM ports 
                WHERE category = 'auth' 
                ORDER BY priority
            """
            results = sync_db.fetch(query)
            
            self.auth_ports = []
            for row in results:
                port_info = {
                    'port': int(row['port']),
                    'priority': int(row['priority']),
                    'enabled': row['enabled'],
                    'description': row['description']
                }
                self.auth_ports.append(port_info)
                
            self.last_refresh['auth_ports'] = time.time()
            logger.debug(f"Loaded {len(self.auth_ports)} authentication/security ports")
        except Exception as e:
            logger.error(f"Failed to load authentication/security ports: {str(e)}")
            self.auth_ports = []
            raise
    
    def _load_mail_ports(self):
        """Load additional mail protocol ports from database"""
        if self.mail_ports is not None and not self._should_reload('mail_ports'):
            logger.debug("Mail ports already loaded, skipping reload")
            return
            
        try:
            query = """
                SELECT port, priority, enabled, description 
                FROM ports 
                WHERE category = 'mail' 
                ORDER BY priority
            """
            results = sync_db.fetch(query)
            
            self.mail_ports = []
            for row in results:
                port_info = {
                    'port': int(row['port']),
                    'priority': int(row['priority']),
                    'enabled': row['enabled'],
                    'description': row['description']
                }
                self.mail_ports.append(port_info)
                
            self.last_refresh['mail_ports'] = time.time()
            logger.debug(f"Loaded {len(self.mail_ports)} mail protocol ports")
        except Exception as e:
            logger.error(f"Failed to load mail protocol ports: {str(e)}")
            self.mail_ports = []
            raise
    
    def reload_all_ports(self):
        """Reload all ports from database"""
        self.smtp_ports = None
        self.dns_ports = None
        self.auth_ports = None
        self.mail_ports = None
        logger.info("All ports marked for reload")
    
    def get_smtp_ports(self) -> List[Dict[str, Any]]:
        """Get all SMTP ports"""
        if self.smtp_ports is None:
            self._load_smtp_ports()
        return self.smtp_ports if self.smtp_ports is not None else []
    
    def get_dns_ports(self):
        """Get all DNS ports (includes DNS, WHOIS, and RDAP)"""
        if self.dns_ports is None:
            self._load_dns_ports()
        return self.dns_ports
    
    def get_dns_only_ports(self):
        """Get only DNS category ports"""
        if self.dns_ports is None:
            self._load_dns_ports()
        if self.dns_ports is None:
            return []
        return [p for p in self.dns_ports if p['category'] == 'dns']
    
    def get_whois_ports(self):
        """Get only WHOIS category ports"""
        if self.dns_ports is None:
            self._load_dns_ports()
        if self.dns_ports is None:
            return []
        return [p for p in self.dns_ports if p['category'] == 'whois']
    
    def get_rdap_ports(self):
        """Get only RDAP category ports"""
        if self.dns_ports is None:
            self._load_dns_ports()
        if self.dns_ports is None:
            return []
        return [p for p in self.dns_ports if p['category'] == 'rdap']
    
    def get_auth_ports(self):
        """Get all authentication and security ports"""
        if self.auth_ports is None:
            self._load_auth_ports()
        return self.auth_ports
    
    def get_mail_ports(self):
        """Get all additional mail protocol ports"""
        if self.mail_ports is None:
            self._load_mail_ports()
        return self.mail_ports
    
    def get_enabled_smtp_ports(self):
        """Get all enabled SMTP ports"""
        if self.smtp_ports is None:
            self._load_smtp_ports()
        if self.smtp_ports is None:
            return []
        return [p for p in self.smtp_ports if p['enabled']]
    
    def get_enabled_dns_ports(self):
        """Get all enabled DNS ports"""
        if self.dns_ports is None:
            self._load_dns_ports()
        if self.dns_ports is None:
            return []
        return [p for p in self.dns_ports if p['enabled']]
    
    def get_enabled_auth_ports(self):
        """Get all enabled authentication and security ports"""
        if self.auth_ports is None:
            self._load_auth_ports()
        if self.auth_ports is None:
            return []
        return [p for p in self.auth_ports if p['enabled']]
    
    def get_enabled_mail_ports(self):
        """Get all enabled additional mail protocol ports"""
        if self.mail_ports is None:
            self._load_mail_ports()
        if self.mail_ports is None:
            return []
        return [p for p in self.mail_ports if p['enabled']]
    
    def get_smtp_ports_by_priority(self, priority):
        """Get SMTP ports with the specified priority"""
        if self.smtp_ports is None:
            self._load_smtp_ports()
        if self.smtp_ports is None:
            return []
        return [p for p in self.smtp_ports if p['priority'] == priority]
    
    def get_dns_ports_by_priority(self, priority):
        """Get DNS ports with the specified priority"""
        if self.dns_ports is None:
            self._load_dns_ports()
        if self.dns_ports is None:
            return []
        return [p for p in self.dns_ports if p['priority'] == priority]
    
    def get_auth_ports_by_priority(self, priority):
        """Get authentication and security ports with the specified priority"""
        if self.auth_ports is None:
            self._load_auth_ports()
        if self.auth_ports is None:
            return []
        return [p for p in self.auth_ports if p['priority'] == priority]
    
    def get_mail_ports_by_priority(self, priority):
        """Get additional mail protocol ports with the specified priority"""
        if self.mail_ports is None:
            self._load_mail_ports()
        if self.mail_ports is None:
            return []
        return [p for p in self.mail_ports if p['priority'] == priority]
    
    def verify_database_connection(self):
        """Verify database connection and reset cached ports"""
        try:
            # Reset all cached settings
            self.smtp_ports = None
            self.dns_ports = None
            self.auth_ports = None
            self.mail_ports = None
            
            # Test database connection with a simple query
            version = sync_db.fetchval("SELECT version()")
            
            # Count port categories
            query = "SELECT COUNT(DISTINCT category) as category_count FROM ports"
            result = sync_db.fetchrow(query)
            
            if result:
                category_count = result['category_count']
                logger.info(f"Port manager: Database connection verified. Found {category_count} port categories. PostgreSQL version: {version}")
                return True
            else:
                logger.error("Port manager: Database connection failed or no port categories found")
                return False
                
        except Exception as e:
            logger.error(f"Port manager: Database verification failed: {str(e)}")
            
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

# Create singleton instance for easy import
port_manager = PortManager()