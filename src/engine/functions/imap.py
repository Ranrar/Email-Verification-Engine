"""
Email Verification Engine - IMAP (Internet Message Access Protocol) Validation
========================================================================
Verifies IMAP availability for email domains and assesses server capabilities.

IMAP Check Process:
1. Extract domain from sender email
2. Query DNS for MX records and common mail server patterns
3. Test IMAP connectivity on standard ports (143 and 993)
4. Parse server capabilities and security features
5. Assess security level and generate recommendations
6. Return IMAP verification results with detailed analysis

Supported Security Features:
- SSL/TLS encryption (port 993)
- STARTTLS support (port 143)
- Various authentication mechanisms (LOGIN, PLAIN, OAUTH2)
- IDLE capability for push notifications
"""

import socket
import ssl
import re
import time
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime

import dns.resolver

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager
from src.managers.time import TimeManager, now_utc, EnhancedOperationTimer
from src.managers.log import get_logger
from src.managers.port import port_manager
from src.helpers.tracer import (
    ensure_trace_id, 
    ensure_context_has_trace_id, 
    trace_function, 
    validate_trace_id,
    create_child_trace_id
)
from src.engine.functions.mx import fetch_mx_records
from src.engine.functions.statistics import DNSServerStats

# Initialize logging
logger = get_logger()

@dataclass
class IMAPRecord:
    """Represents an IMAP server capabilities"""
    host: str = ""
    port: int = 0
    protocol: str = "IMAP"
    capabilities: List[str] = field(default_factory=list)
    secure_connection: bool = False
    banner: str = ""
    error: str = ""
    supports_starttls: bool = False
    supports_login: bool = False
    supports_plain: bool = False
    supports_oauth: bool = False
    supports_idle: bool = False
    success: bool = False

@dataclass
class IMAPResult:
    """IMAP validation result"""
    domain: str = ""
    has_imap: bool = False
    error: str = ""
    timestamp: datetime = field(default_factory=now_utc)
    duration_ms: int = 0
    servers_checked: List[Dict[str, Any]] = field(default_factory=list)
    imap_servers: List[IMAPRecord] = field(default_factory=list)
    security_level: str = "unknown"  # none, low, medium, high
    recommendations: List[str] = field(default_factory=list)
    supports_ssl: bool = False
    supports_starttls: bool = False
    supports_oauth: bool = False

class IMAPVerifier:
    """
    Class to verify IMAP capabilities of email domains.
    Performs tests on ports 143 (with STARTTLS) and 993 (SSL/TLS).
    """
    
    def __init__(self):
        """Initialize with required managers and settings."""
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        self.time_manager = TimeManager()
        
        # Initialize statistics tracker
        self.dns_stats = DNSServerStats()
        
        # Load IMAP-specific rate limits from the "imap" category
        self.imap_connection_limit = self.rate_limit_manager.get_imap_limit('imap_connection_limit_per_min')
        self.imap_concurrent_sessions = self.rate_limit_manager.get_imap_limit('imap_concurrent_sessions')
        self.timeout_connect = self.rate_limit_manager.get_imap_limit('timeout_connect')
        self.timeout_login = self.rate_limit_manager.get_imap_limit('timeout_login')
        self.timeout_read = self.rate_limit_manager.get_imap_limit('timeout_read')
        self.timeout_idle = self.rate_limit_manager.get_imap_limit('timeout_idle')
        self.connection_timeout = self.rate_limit_manager.get_imap_limit('connection_timeout')
        self.max_login_failures = self.rate_limit_manager.get_imap_limit('max_login_failures_per_min')
        self.block_duration_after_failures = self.rate_limit_manager.get_imap_limit('block_duration_after_failures')
        
        # IMAP default timeout
        self.imap_timeout = self.connection_timeout
        
        # Load IMAP ports from schema
        self.ports = self._load_imap_ports()
        if not self.ports:
            raise ValueError("No IMAP ports loaded from schema")
            
        # Use IMAP-specific cache TTL
        self.imap_cache_ttl = self.rate_limit_manager.get_imap_limit('imap_capabilities_cache_ttl')
        
        logger.info(f"IMAP Verifier initialized with {len(self.ports)} ports, "
                   f"Connection limit: {self.imap_connection_limit}/min, "
                   f"Concurrent sessions: {self.imap_concurrent_sessions}, "
                   f"Connect timeout: {self.timeout_connect}s, "
                   f"Overall timeout: {self.connection_timeout}s, "
                   f"Cache TTL: {self.imap_cache_ttl}s")

    def _load_imap_ports(self) -> Dict[int, Dict[str, Any]]:
        """Load IMAP ports from the schema ports table"""
        ports = {}
        
        # Get mail ports from port manager
        mail_ports = port_manager.get_mail_ports()
        
        if mail_ports is None:
            logger.warning("No mail ports found in port manager")
            # Use hardcoded defaults if no ports found
            ports = {
                143: {'port': 143, 'priority': 4, 'enabled': True, 'description': 'IMAP - Default port', 'uses_ssl': False, 'supports_starttls': True},
                993: {'port': 993, 'priority': 5, 'enabled': True, 'description': 'IMAP - Secure port', 'uses_ssl': True, 'supports_starttls': False}
            }
        else:
            # Filter for IMAP ports (those containing 'IMAP' in the description)
            imap_ports = [port for port in mail_ports if 'IMAP' in port.get('description', '')]
            
            if not imap_ports:
                logger.warning("No IMAP ports found in mail_ports configuration")
                # Use hardcoded defaults if no IMAP ports found
                ports = {
                    143: {'port': 143, 'priority': 4, 'enabled': True, 'description': 'IMAP - Default port', 'uses_ssl': False, 'supports_starttls': True},
                    993: {'port': 993, 'priority': 5, 'enabled': True, 'description': 'IMAP - Secure port', 'uses_ssl': True, 'supports_starttls': False}
                }
            else:
                # Use the filtered IMAP ports
                for port_info in imap_ports:
                    port_num = port_info['port']
                    ports[port_num] = port_info

        logger.info(f"Loaded {len(ports)} IMAP ports: {list(ports.keys())}")
        
        # If no ports found, raise exception
        if not ports:
            logger.error("Failed to load any IMAP ports")
            raise ValueError("No IMAP ports available")
            
        return ports

    def get_enabled_imap_ports(self) -> Dict[int, Dict[str, Any]]:
        """Get only enabled IMAP ports"""
        return {port: info for port, info in self.ports.items() if info.get('enabled', True)}

    def get_imap_ports_by_priority(self) -> List[Tuple[int, Dict[str, Any]]]:
        """Get IMAP ports sorted by priority"""
        port_items = [(port, info) for port, info in self.ports.items() if info.get('enabled', True)]
        return sorted(port_items, key=lambda x: x[1].get('priority', 999))

    def reload_ports(self):
        """Reload ports from schema (useful for runtime updates)"""
        old_port_count = len(self.ports)
        self.ports = self._load_imap_ports()
        new_port_count = len(self.ports)
        
        logger.info(f"Reloaded IMAP ports: {old_port_count} -> {new_port_count} ports")
        return self.ports

    @trace_function("check_imap")
    def check_imap(self, domain: str, trace_id: Optional[str] = None) -> IMAPResult:
        """Check IMAP availability for a domain."""
        trace_id = ensure_trace_id(trace_id)
        child_trace_id = create_child_trace_id(trace_id)
        
        start_time = datetime.now()
        logger.debug(f"[{child_trace_id}] Starting IMAP check for {domain}")
        
        cache_key = CacheKeys.imap(domain)
        
        cached_result = cache_manager.get(cache_key)
        if cached_result:
            logger.info(f"[{child_trace_id}] Cache hit for {domain} IMAP verification")
            if isinstance(cached_result, dict):
                return IMAPResult(
                    domain=cached_result.get("domain", domain),
                    has_imap=cached_result.get("has_imap", False),
                    error=cached_result.get("error", ""),
                    timestamp=now_utc(),
                    duration_ms=cached_result.get("duration_ms", 0),
                    servers_checked=cached_result.get("servers_checked", []),
                    imap_servers=cached_result.get("imap_servers", []),
                    security_level=cached_result.get("security_level", "unknown"),
                    recommendations=cached_result.get("recommendations", []),
                    supports_ssl=cached_result.get("supports_ssl", False),
                    supports_starttls=cached_result.get("supports_starttls", False),
                    supports_oauth=cached_result.get("supports_oauth", False)
                )
            return cached_result
        
        # Check rate limits
        current_connections = self._get_current_imap_connections(domain)
        if current_connections >= self.imap_connection_limit:
            logger.warning(f"[{child_trace_id}] IMAP connection rate limit exceeded for {domain}: "
                          f"{current_connections}/{self.imap_connection_limit} per minute")
            return IMAPResult(
                domain=domain,
                has_imap=False,
                error=f"Rate limit exceeded: {current_connections}/{self.imap_connection_limit} connections per minute",
                timestamp=now_utc(),
                duration_ms=0
            )
        
        # Use enhanced timer to measure operation duration
        with EnhancedOperationTimer("imap_lookup", metadata={"domain": domain}) as timer:
            # Initialize hosts_to_check before the try-except block to ensure it is always defined
            hosts_to_check = []
            # Initialize mx_result with a default value
            mx_result = {"records": [], "valid": False, "error": None}
            
            try:
                # First, get MX records to find potential mail servers
                logger.info(f"[{child_trace_id}] Fetching MX records for {domain}")
                logger.debug(f"[{child_trace_id}] Calling fetch_mx_records for domain: {domain}")
                
                # Before we call fetch_mx_records, check if domain is actually an email address
                original_input = domain  # Save the original input
                is_email = '@' in domain
                actual_domain = domain.split('@')[1] if is_email else domain

                # If the original input was an email, use it directly
                if is_email:
                    logger.debug(f"[{trace_id}] Using original email for MX lookup: {original_input}")
                    mx_result = fetch_mx_records({"email": original_input, "trace_id": trace_id})
                else:
                    logger.debug(f"[{trace_id}] Using constructed email for MX lookup: postmaster@{domain}")
                    mx_result = fetch_mx_records({"email": f"postmaster@{domain}", "trace_id": trace_id})
                
                # Log the results
                logger.debug(f"[{child_trace_id}] MX lookup returned: valid={mx_result.get('valid')}, error={mx_result.get('error', 'None')}")
                if mx_result.get('records'):
                    logger.info(f"[{child_trace_id}] Found {len(mx_result.get('records'))} MX records for {domain}")
                    
                # Extract MX records from the result and add to hosts_to_check
                if mx_result.get('records'):
                    for mx_record in mx_result.get('records', []):
                        exchange = mx_record.get('exchange', '')
                        if exchange and exchange not in hosts_to_check:
                            hosts_to_check.append(exchange)
                            logger.info(f"[{child_trace_id}] Added MX host for IMAP check: {exchange}")
                
            except Exception as e:
                logger.error(f"[{child_trace_id}] Error in MX lookup: {e}")
                # Continue with fallback approach on MX fetch error

        # If no valid MX hosts found, add domain itself and check for its existence
        if not hosts_to_check:
            # Check if domain itself exists via DNS
            if self._check_host_exists(domain, child_trace_id):
                hosts_to_check.append(domain)
                logger.info(f"[{child_trace_id}] Added domain itself for IMAP check: {domain}")
            else:
                logger.info(f"[{child_trace_id}] Domain {domain} does not exist in DNS, skipping")
            
            # Check and add common patterns, but only if they exist
            for pattern in ["mail", "imap", "webmail", "pop", "exchange"]:
                pattern_host = f"{pattern}.{domain}"
                if self._check_host_exists(pattern_host, child_trace_id):
                    hosts_to_check.append(pattern_host)
                    logger.debug(f"[{child_trace_id}] Added pattern host: {pattern_host}")
                else:
                    logger.debug(f"[{child_trace_id}] Pattern host {pattern_host} does not exist in DNS, skipping")
        
        # Track results for all hosts
        results = []
        successful_servers = []
        has_imap = False
        current_concurrent = 0
        
        # Check each host
        for host in hosts_to_check:
            host_result = {
                "host": host,
                "ports_checked": []
            }
            
            # Get enabled ports sorted by priority
            enabled_ports = self.get_enabled_imap_ports()
            priority_sorted_ports = self.get_imap_ports_by_priority()
            
            for port, port_info in priority_sorted_ports:
                # Check concurrent session limit
                if current_concurrent >= self.imap_concurrent_sessions:
                    logger.warning(f"[{child_trace_id}] IMAP concurrent session limit reached: "
                                  f"{current_concurrent}/{self.imap_concurrent_sessions}")
                    break
                
                # Skip disabled ports
                if not port_info.get("enabled", True):
                    logger.debug(f"[{child_trace_id}] Skipping disabled port {port} for {host}")
                    continue
                
                use_ssl = port_info.get("secure", False)
                
                logger.debug(f"[{child_trace_id}] Testing {host}:{port} ({port_info.get('protocol', 'IMAP')}) - Priority: {port_info.get('priority', 999)}")
                
                # Try to connect
                success, port_result = self._connect_to_imap_server(
                    host, 
                    port, 
                    use_ssl=use_ssl, 
                    timeout=self.imap_timeout
                )
                
                current_concurrent += 1  # Track concurrent connections
                
                host_result["ports_checked"].append({
                    "port": port,
                    "success": success,
                    "priority": port_info.get('priority', 999),
                    "protocol": port_info.get('protocol', 'IMAP'),
                    **port_result
                })
                
                # Record successful server
                if success:
                    has_imap = True
                    server_info = {
                        "host": host,
                        "port": port,
                        "protocol": port_info.get("protocol", "IMAP"),
                        "secure": port_info.get("secure", False),
                        "capabilities": port_result.get("capabilities", []),
                        "banner": port_result.get("banner", ""),
                        "priority": port_info.get("priority", 999)
                    }
                    successful_servers.append(server_info)
                
                # Record connection attempt for rate limiting
                self._record_imap_connection(domain)
                
                # Small delay between connections
                time.sleep(0.2)
        
        # Convert dictionary results to IMAPRecord objects
        imap_server_records = []
        for server in successful_servers:
            imap_record = IMAPRecord(
                host=server.get("host", ""),
                port=server.get("port", 0),
                protocol=server.get("protocol", "IMAP"),
                capabilities=server.get("capabilities", []),
                secure_connection=server.get("secure", False),
                banner=server.get("banner", ""),
                supports_starttls=server.get("supports_starttls", False),
                supports_login=server.get("supports_login", False),
                supports_plain=server.get("supports_plain", False),
                supports_oauth=server.get("supports_oauth", False),
                supports_idle=server.get("supports_idle", False),
                success=True
            )
            imap_server_records.append(imap_record)
    
        # Assess security and generate recommendations
        security_level = self._assess_imap_security(imap_server_records, child_trace_id)
        recommendations = self._generate_recommendations(imap_server_records, child_trace_id)
        
        # Create final result with correct duration
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        final_result = IMAPResult(
            domain=domain,
            has_imap=has_imap,
            imap_servers=imap_server_records,
            servers_checked=results,
            timestamp=now_utc(),
            duration_ms=duration_ms,
            security_level=security_level,
            recommendations=recommendations,
            supports_ssl=any(server.secure_connection for server in imap_server_records),
            supports_starttls=any(server.supports_starttls for server in imap_server_records),
            supports_oauth=any(server.supports_oauth for server in imap_server_records)
        )
        
        # Record statistics
        self._record_imap_statistics(final_result, child_trace_id)
        
        # Cache the result using schema-defined TTL
        cache_manager.set(cache_key, final_result, ttl=self.imap_cache_ttl)
        logger.info(f"[{child_trace_id}] Cached IMAP verification for {domain}: has_imap={has_imap}")
        
        return final_result
    
    def _get_current_imap_connections(self, domain: str) -> int:
        """Get current IMAP connection count for rate limiting"""
        # Use rate_limit_manager to get current usage count - also fix this call
        count = self.rate_limit_manager.get_usage_count('imap', f'imap_connection_limit_per_min:{domain}')
        logger.debug(f"Current IMAP connections for {domain}: {count}")
        return count

    def _record_imap_connection(self, domain: str):
        """Record IMAP connection attempt for rate limiting"""
        # Record usage in the rate limit manager - combine resource_id with domain
        self.rate_limit_manager.record_usage('imap', f'imap_connection_limit_per_min:{domain}')
        logger.debug(f"Recorded IMAP connection attempt for {domain}")

    @trace_function("assess_imap_security")
    def _assess_imap_security(self, imap_servers: List[IMAPRecord], trace_id: str) -> str:
        """
        Assess security level of IMAP servers
        
        Args:
            imap_servers: List of IMAP server records
            trace_id: Trace ID for logging
            
        Returns:
            Security level classification: none, low, medium, high
        """
        # Validate trace ID
        if not validate_trace_id(trace_id):
            logger.error(f"Invalid trace_id received: {trace_id}")
            trace_id = ensure_trace_id()
        
        if not imap_servers:
            logger.debug(f"[{trace_id}] No IMAP servers found to assess")
            return "none"
        
        # Count secure servers and features
        secure_servers = sum(1 for server in imap_servers if server.secure_connection)
        starttls_supported = any(server.supports_starttls for server in imap_servers)
        oauth_supported = any(server.supports_oauth for server in imap_servers)
        modern_auth = oauth_supported
        
        # Determine security level
        if not secure_servers and not starttls_supported:
            logger.debug(f"[{trace_id}] IMAP security level: none - No encryption")
            return "none"
        elif secure_servers > 0 and modern_auth:
            logger.debug(f"[{trace_id}] IMAP security level: high - SSL/TLS with modern auth")
            return "high"
        elif secure_servers > 0 or starttls_supported:
            logger.debug(f"[{trace_id}] IMAP security level: medium - Some encryption")
            return "medium"
        else:
            logger.debug(f"[{trace_id}] IMAP security level: low - Limited security")
            return "low"

    @trace_function("generate_imap_recommendations")
    def _generate_recommendations(self, imap_servers: List[IMAPRecord], trace_id: str) -> List[str]:
        """
        Generate recommendations for IMAP security improvements
        
        Args:
            imap_servers: List of IMAP server records
            trace_id: Trace ID for logging
            
        Returns:
            List of security recommendations
        """
        # Validate trace ID
        if not validate_trace_id(trace_id):
            logger.error(f"Invalid trace_id received in _generate_recommendations: {trace_id}")
            trace_id = ensure_trace_id()
        
        recommendations = []
        
        if not imap_servers:
            recommendations.append("Configure IMAP servers to provide email access capabilities")
            return recommendations
        
        # Check for SSL/TLS support
        has_ssl = any(server.secure_connection for server in imap_servers)
        if not has_ssl:
            recommendations.append("Enable SSL/TLS on IMAP servers (port 993) for improved security")
        
        # Check for STARTTLS
        has_starttls = any(server.supports_starttls for server in imap_servers)
        if not has_starttls and not has_ssl:
            recommendations.append("Enable STARTTLS support on standard IMAP port (143)")
        
        # Check for OAuth
        has_oauth = any(server.supports_oauth for server in imap_servers)
        if not has_oauth:
            recommendations.append("Add OAuth 2.0 authentication support for better security than plain-text passwords")
        
        # Check for IDLE capability
        has_idle = any(server.supports_idle for server in imap_servers)
        if not has_idle:
            recommendations.append("Enable IDLE capability for push email notifications")
        
        # If everything looks good
        if has_ssl and has_oauth and has_idle and not recommendations:
            recommendations.append("IMAP configuration follows current security best practices")
        
        logger.debug(f"[{trace_id}] Generated {len(recommendations)} recommendations for IMAP configuration")
        return recommendations

    def _record_imap_statistics(self, result: IMAPResult, trace_id: str):
        """Record IMAP validation statistics"""
        try:
            # Ensure DNS stats is available
            if self.dns_stats is None:
                try:
                    self.dns_stats = DNSServerStats()
                except Exception as e:
                    logger.debug(f"[{trace_id}] Could not initialize DNS stats: {e}")
                    return  # Exit early if stats unavailable
        
            # Record main IMAP statistics
            self.dns_stats.record_imap_statistics(
                trace_id=trace_id,
                domain=result.domain,
                has_imap=result.has_imap,
                servers_found=len(result.imap_servers),
                security_level=result.security_level,
                supports_ssl=result.supports_ssl,
                supports_starttls=result.supports_starttls,
                supports_oauth=result.supports_oauth,
                dns_lookups=len(result.servers_checked),
                processing_time_ms=float(result.duration_ms),
                errors=result.error if result.error else None
            )
            
            # Store detailed analysis
            analysis_result = {
                'has_imap': result.has_imap,
                'servers_found': len(result.imap_servers),
                'security_level': result.security_level,
                'supports_ssl': result.supports_ssl,
                'supports_starttls': result.supports_starttls,
                'supports_oauth': result.supports_oauth,
                'dns_lookups': len(result.servers_checked),
                'execution_time_ms': result.duration_ms,
                'errors': [result.error] if result.error else [],
                'warnings': [],
                'recommendations': result.recommendations
            }
            
            self.dns_stats.store_imap_analysis(result.domain, analysis_result, trace_id)
            
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to record IMAP statistics: {e}")
    
    def _connect_to_imap_server(self, host, port, use_ssl=False, timeout=None):
        """Improved IMAP connection with strict timeouts"""
        result = {
            "capabilities": [],
            "banner": "",
            "supports_starttls": False,
            "supports_login": False,
            "supports_plain": False,
            "supports_oauth": False,
            "supports_idle": False,
            "error": ""
        }
        
        timeout = timeout or self.timeout_connect
        logger.debug(f"Connecting to {host}:{port} (SSL: {use_ssl}, timeout: {timeout}s)")
        
        # Add timeout for DNS resolution
        socket.setdefaulttimeout(timeout)
        sock = None
        
        try:
            # Create socket with explicit timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Start connection timer and set deadline
            start_time = time.time()
            deadline = start_time + timeout
            
            # Connect with timeout
            try:
                sock.connect((host, port))
            except socket.timeout:
                return False, {"error": f"Connection timeout after {timeout}s", "banner": "", "capabilities": []}
            except socket.gaierror as e:
                if "Name or service not known" in str(e):
                    return False, {"error": "DNS resolution error", "banner": "", "capabilities": []}
                return False, {"error": f"Connection error: {str(e)}", "banner": "", "capabilities": []}
            except ConnectionRefusedError:
                return False, {"error": "Connection refused", "banner": "", "capabilities": []}
            except Exception as e:
                return False, {"error": f"Connection error: {str(e)}", "banner": "", "capabilities": []}
        
            # Wrap socket if SSL is required
            if use_ssl:
                try:
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = context.wrap_socket(sock, server_hostname=host)
                except ssl.SSLError as e:
                    return False, {"error": f"SSL error: {str(e)}", "banner": "", "capabilities": []}
                except Exception as e:
                    return False, {"error": f"SSL wrapper error: {str(e)}", "banner": "", "capabilities": []}
        
            # Read banner
            try:
                remaining = max(0.5, deadline - time.time())
                sock.settimeout(remaining)
                banner_data = sock.recv(1024)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                result["banner"] = banner
                
                if not banner or not banner.startswith("* OK"):
                    return False, {"error": f"Invalid IMAP banner: {banner}", "banner": banner, "capabilities": []}
            except socket.timeout:
                return False, {"error": "Timeout waiting for banner", "banner": "", "capabilities": []}
            except Exception as e:
                return False, {"error": f"Error reading banner: {str(e)}", "banner": "", "capabilities": []}
            
            # Send CAPABILITY command and read response
            capabilities = []
            try:
                remaining = max(0.5, deadline - time.time())
                sock.settimeout(remaining)
                sock.send(b"A001 CAPABILITY\r\n")
                
                response = b""
                while remaining > 0:
                    remaining = max(0.1, deadline - time.time())
                    sock.settimeout(remaining)
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if b"A001 OK" in response or b"A001 BAD" in response or b"A001 NO" in response:
                        break
                
                resp_str = response.decode('utf-8', errors='ignore')
                
                for line in resp_str.splitlines():
                    if "* CAPABILITY" in line:
                        cap_parts = line.split("* CAPABILITY")[1].strip().split()
                        capabilities = [cap.upper() for cap in cap_parts]
                        result["capabilities"] = capabilities
                        break
            except socket.timeout:
                return False, {"error": "Timeout reading capabilities", "banner": banner, "capabilities": []}
            except Exception as e:
                return False, {"error": f"Error processing capabilities: {str(e)}", "banner": banner, "capabilities": []}
        
            # Process capabilities
            result["supports_starttls"] = "STARTTLS" in capabilities
            result["supports_login"] = any("LOGIN" in cap for cap in capabilities)
            result["supports_plain"] = any("PLAIN" in cap for cap in capabilities)
            result["supports_oauth"] = any("OAUTH" in cap for cap in capabilities) or any("XOAUTH" in cap for cap in capabilities)
            result["supports_idle"] = "IDLE" in capabilities
        
            # Clean logout
            try:
                sock.send(b"A002 LOGOUT\r\n")
                sock.settimeout(1.0)
                sock.recv(1024)
            except:
                pass
        
            return True, result
        
        except Exception as e:
            # Handle any uncaught exceptions
            return False, {"error": f"Unexpected error: {str(e)}", "banner": result.get("banner", ""), "capabilities": result.get("capabilities", [])}
    
        finally:
            # Always clean up resources
            socket.setdefaulttimeout(None)
            if sock:
                try:
                    sock.close()
                except:
                    pass

    # Test multiple ports on same host more efficiently
    def _test_host_ports(self, host: str, ports: List[int]) -> Dict[int, Any]:
        """Test multiple ports on the same host efficiently"""
        results = {}
        for port in ports:
            # Add small delay between tests to avoid overwhelming the server
            if results:  # Not the first test
                time.sleep(0.5)
            results[port] = self._connect_to_imap_server(host, port)
        return results

    def _check_host_exists(self, hostname: str, trace_id: str) -> bool:
        """Check if hostname exists in DNS using A or AAAA records"""
        try:
            # Try to get from cache first
            cache_key = CacheKeys.host_exists(hostname)
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"[{trace_id}] Cache hit for host existence check: {hostname}")
                return cached_result
            
            # Try A record first
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                if answers:
                    cache_manager.set(cache_key, True, ttl=3600)  # Cache for 1 hour
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # If A record fails, try AAAA
                try:
                    answers = dns.resolver.resolve(hostname, 'AAAA')
                    if answers:
                        cache_manager.set(cache_key, True, ttl=3600)
                        return True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # If both fail, the host doesn't exist
                    cache_manager.set(cache_key, False, ttl=300)  # Cache negative result for 5 minutes
                    return False
            
            # Default fallback - shouldn't reach here
            return False
        except Exception as e:
            logger.warning(f"[{trace_id}] Error checking if host {hostname} exists: {e}")
            return False  # Assume host doesn't exist if we encounter errors

@trace_function("imap_check")
def imap_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    IMAP validation function for the Email Verification Engine
    
    Args:
        context: Dictionary containing:
            - email: Email address being validated
            - trace_id: Optional trace ID for logging
            
    Returns:
        Dict with IMAP validation results
    """
    # Ensure context has valid trace_id
    context = ensure_context_has_trace_id(context)
    trace_id = context['trace_id']
    
    email = context.get("email", "")
    
    if not email or '@' not in email:
        raise ValueError("Invalid email format, cannot extract domain")
    
    # Extract domain from email
    domain = email.split('@')[1].lower().strip()
    
    logger.info(f"[{trace_id}] Starting IMAP validation for {email} (domain: {domain})")
    
    # Initialize IMAP verifier with child trace
    child_trace_id = create_child_trace_id(trace_id)
    verifier = IMAPVerifier()
    
    # Perform IMAP validation
    start_time = time.time()
    result = verifier.check_imap(domain, child_trace_id)
    
    # Convert to dictionary format for consistency with other modules
    if not result.has_imap and not result.error:
        result.error = "No IMAP server found or connection failed"
    response = {
        "valid": result.has_imap,
        "has_imap": result.has_imap,
        "domain": domain,
        "servers": [vars(server) for server in result.imap_servers],
        "security_level": result.security_level,
        "recommendations": result.recommendations,
        "supports_ssl": result.supports_ssl,
        "supports_starttls": result.supports_starttls,
        "supports_oauth": result.supports_oauth,
        "execution_time": result.duration_ms,
        "error": result.error
    }
    
    logger.info(f"[{trace_id}] Completed IMAP validation for {domain}: has_imap={result.has_imap}")
    return response
