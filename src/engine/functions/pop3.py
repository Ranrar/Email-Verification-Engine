"""
Email Verification Engine - POP3 (Post Office Protocol 3) Validation
========================================================================
Verifies POP3 availability for email domains and assesses server capabilities.

POP3 Check Process:
1. Extract domain from sender email
2. Query DNS for MX records and common mail server patterns
3. Test POP3 connectivity on standard ports (110 and 995)
4. Parse server capabilities and security features
5. Assess security level and generate recommendations
6. Return POP3 verification results with detailed analysis

Supported Security Features:
- SSL/TLS encryption (port 995)
- STARTTLS support (port 110)
- Various authentication mechanisms (USER/PASS, APOP, OAUTH2)
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
class POP3Record:
    """Represents a POP3 server capabilities"""
    host: str = ""
    port: int = 0
    protocol: str = "POP3"
    capabilities: List[str] = field(default_factory=list)
    secure_connection: bool = False
    banner: str = ""
    error: str = ""
    supports_starttls: bool = False
    supports_user_pass: bool = False
    supports_apop: bool = False
    supports_oauth: bool = False
    supports_top: bool = False
    supports_uidl: bool = False
    success: bool = False

@dataclass
class POP3Result:
    """POP3 validation result"""
    domain: str = ""
    has_pop3: bool = False
    pop3_servers: List[POP3Record] = field(default_factory=list)
    servers_checked: List[str] = field(default_factory=list)
    security_level: str = "none"
    supports_ssl: bool = False
    supports_starttls: bool = False
    supports_oauth: bool = False
    recommendations: List[str] = field(default_factory=list)
    error: str = ""
    duration_ms: float = 0.0
    trace_id: str = ""

class POP3Verifier:
    """
    Class to verify POP3 capabilities of email domains.
    Performs tests on ports 110 (with STARTTLS) and 995 (SSL/TLS).
    """
    
    def __init__(self):
        """Initialize with required managers and settings."""
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        self.time_manager = TimeManager()
        
        # Load POP3-specific settings from rate limit manager
        try:
            self.connection_timeout = self.rate_limit_manager.get_pop3_connect_timeout()
            self.read_timeout = self.rate_limit_manager.get_pop3_read_timeout()
            self.max_concurrent_sessions = self.rate_limit_manager.get_pop3_concurrent_sessions()
            self.max_connections_per_minute = self.rate_limit_manager.get_pop3_connection_limit()
        except Exception as e:
            logger.error(f"Failed to load POP3 rate limits from database: {e}")
            raise RuntimeError(f"Cannot initialize POP3Verifier without rate limit settings: {e}")
        
        # Get POP3 ports from port manager
        try:
            # Get mail category ports and filter for POP3
            mail_ports = port_manager.get_enabled_mail_ports()
            self.pop3_ports = []
            
            for port_info in mail_ports:
                port_num = port_info['port']
                description = port_info.get('description', '').lower()
                
                # Identify POP3 ports based on standard ports and descriptions
                if port_num == 110:
                    self.pop3_ports.append({
                        "port": 110, 
                        "ssl": False, 
                        "protocol": "POP3",
                        "priority": port_info.get('priority', 20),
                        "supports_starttls": True
                    })
                elif port_num == 995:
                    self.pop3_ports.append({
                        "port": 995, 
                        "ssl": True, 
                        "protocol": "POP3S",
                        "priority": port_info.get('priority', 10),
                        "supports_starttls": False
                    })
                elif 'pop3' in description:
                    # Handle custom POP3 ports
                    is_ssl = 'ssl' in description or 'tls' in description or port_num == 995
                    self.pop3_ports.append({
                        "port": port_num,
                        "ssl": is_ssl,
                        "protocol": "POP3S" if is_ssl else "POP3",
                        "priority": port_info.get('priority', 30),
                        "supports_starttls": not is_ssl
                    })
            
            # Sort by priority (lower number = higher priority)
            self.pop3_ports.sort(key=lambda x: x['priority'])
            
            if not self.pop3_ports:
                logger.error("No POP3 ports found in database")
                raise RuntimeError("Cannot initialize POP3Verifier: No POP3 ports configured in database")
                
        except Exception as e:
            logger.error(f"Failed to load POP3 ports from database: {e}")
            raise RuntimeError(f"Cannot initialize POP3Verifier without port configuration: {e}")
        
        logger.info(f"POP3Verifier initialized with {len(self.pop3_ports)} ports, "
                   f"timeouts: connect={self.connection_timeout}s, read={self.read_timeout}s")
    
    @trace_function("check_pop3")
    def check_pop3(self, domain: str, trace_id: Optional[str] = None) -> POP3Result:
        """Check POP3 availability for a domain."""
        trace_id = ensure_trace_id(trace_id)
        
        with EnhancedOperationTimer("pop3_check", metadata={"domain": domain}) as timer:
            result = POP3Result(domain=domain, trace_id=trace_id)
            
            try:
                # Check cache first
                cache_key = CacheKeys.pop3(domain)
                cached_result = cache_manager.get(cache_key)
                
                if cached_result:
                    logger.info(f"[{trace_id}] Cache hit for POP3 check of {domain}")
                    # Convert cached data back to POP3Result
                    result.has_pop3 = cached_result.get('has_pop3', False)
                    result.security_level = cached_result.get('security_level', 'none')
                    result.supports_ssl = cached_result.get('supports_ssl', False)
                    result.supports_starttls = cached_result.get('supports_starttls', False)
                    result.supports_oauth = cached_result.get('supports_oauth', False)
                    result.recommendations = cached_result.get('recommendations', [])
                    result.servers_checked = cached_result.get('servers_checked', [])
                    
                    # Reconstruct POP3Record objects
                    result.pop3_servers = []
                    for server_data in cached_result.get('pop3_servers', []):
                        server = POP3Record()
                        for key, value in server_data.items():
                            if hasattr(server, key):
                                setattr(server, key, value)
                        result.pop3_servers.append(server)
                    
                    result.duration_ms = float(timer.elapsed_ms) if timer.elapsed_ms is not None else 0.0
                    return result
                
                # Step 1: Get MX records for the domain using existing infrastructure
                logger.info(f"[{trace_id}] Starting POP3 check for {domain}")
                mx_context = {"email": f"test@{domain}", "trace_id": trace_id}
                mx_result = fetch_mx_records(mx_context)
                
                if not mx_result.get("valid") or not mx_result.get("records"):
                    if mx_result.get("error") == "Domain does not exist":
                        result.error = "Domain does not exist"
                        result.duration_ms = float(timer.elapsed_ms) if timer.elapsed_ms is not None else 0.0
                        return result
                    
                    # No MX records, try the domain directly
                    logger.info(f"[{trace_id}] No MX records for {domain}, testing domain directly")
                    hosts_to_test = [domain]
                else:
                    # Extract MX hosts
                    hosts_to_test = [mx["exchange"] for mx in mx_result["records"]]
                    logger.info(f"[{trace_id}] Found {len(hosts_to_test)} MX hosts for {domain}")
                
                # Step 2: Test POP3 on each host
                pop3_servers = []
                servers_checked = []
                
                for host in hosts_to_test:
                    servers_checked.append(host)
                    
                    # Check rate limits per host
                    is_exceeded, limit_info = self.rate_limit_manager.check_rate_limit(
                        'pop3', host, 'connection_limit_per_min'
                    )
                    if is_exceeded:
                        logger.warning(f"[{trace_id}] Rate limit exceeded for {host}: "
                                     f"{limit_info.get('current')}/{limit_info.get('limit')} "
                                     f"per {limit_info.get('period')}")
                        continue
                    
                    # Test each port configuration
                    for port_config in self.pop3_ports:
                        port = port_config["port"]
                        use_ssl = port_config["ssl"]
                        
                        # Test connection with timing
                        with EnhancedOperationTimer(f"pop3_connection_{host}_{port}", 
                                                  metadata={"host": host, "port": port, "ssl": use_ssl}) as conn_timer:
                            
                            pop3_record = self._connect_to_pop3_server(
                                host, port, use_ssl, self.connection_timeout, trace_id
                            )
                        
                        if pop3_record.success:
                            pop3_servers.append(pop3_record)
                            logger.info(f"[{trace_id}] POP3 connection successful: {host}:{port} "
                                      f"({pop3_record.protocol}) in {conn_timer.elapsed_ms:.2f}ms")
                            
                            # Record successful usage
                            self.rate_limit_manager.record_usage('pop3', host)
                            break  # Stop testing other ports for this host once we find a working one
                        else:
                            logger.debug(f"[{trace_id}] POP3 connection failed: {host}:{port} - {pop3_record.error}")
                
                # Step 3: Analyze results and determine security level
                result.pop3_servers = pop3_servers
                result.servers_checked = servers_checked
                result.has_pop3 = len(pop3_servers) > 0
                
                # Determine security capabilities
                result.supports_ssl = any(server.secure_connection for server in pop3_servers)
                result.supports_starttls = any(server.supports_starttls for server in pop3_servers)
                result.supports_oauth = any(server.supports_oauth for server in pop3_servers)
                
                # Assess security level
                result.security_level = self._assess_security_level(result)
                
                # Generate recommendations
                result.recommendations = self._generate_recommendations(result)
                
                result.duration_ms = float(timer.elapsed_ms) if timer.elapsed_ms is not None else 0.0
                
                # Cache the result
                try:
                    cache_ttl = self.rate_limit_manager.get_pop3_capabilities_cache_ttl()
                    
                    # Prepare data for caching (convert POP3Record objects to dicts)
                    cache_data = {
                        'has_pop3': result.has_pop3,
                        'security_level': result.security_level,
                        'supports_ssl': result.supports_ssl,
                        'supports_starttls': result.supports_starttls,
                        'supports_oauth': result.supports_oauth,
                        'recommendations': result.recommendations,
                        'servers_checked': result.servers_checked,
                        'pop3_servers': [
                            {
                                'host': server.host,
                                'port': server.port,
                                'protocol': server.protocol,
                                'capabilities': server.capabilities,
                                'secure_connection': server.secure_connection,
                                'banner': server.banner,
                                'supports_starttls': server.supports_starttls,
                                'supports_user_pass': server.supports_user_pass,
                                'supports_apop': server.supports_apop,
                                'supports_oauth': server.supports_oauth,
                                'supports_top': server.supports_top,
                                'supports_uidl': server.supports_uidl,
                                'success': server.success
                            } for server in pop3_servers
                        ],
                        'cached_at': now_utc().isoformat()
                    }
                    
                    cache_manager.set(cache_key, cache_data, ttl=cache_ttl)
                    logger.debug(f"[{trace_id}] Cached POP3 result for {domain} with TTL {cache_ttl}s")
                    
                except Exception as cache_error:
                    logger.error(f"[{trace_id}] Failed to get cache TTL from database for POP3 result: {cache_error}")
                    # Don't cache if we can't get TTL from database

                # Record statistics
                self._record_pop3_statistics(result, dns_lookups=1)
                
                logger.info(f"[{trace_id}] POP3 check completed for {domain}: "
                          f"found {len(pop3_servers)} servers, security: {result.security_level}")
                
                return result
                
            except Exception as e:
                result.error = f"POP3 check failed: {str(e)}"
                result.duration_ms = float(timer.elapsed_ms) if timer.elapsed_ms is not None else 0.0
                logger.error(f"[{trace_id}] POP3 check error for {domain}: {e}")
                return result
    
    def _connect_to_pop3_server(self, host: str, port: int, use_ssl: bool = False, 
                               timeout: float = 10.0, trace_id: str = "") -> POP3Record:
        """Connect to POP3 server and get capabilities"""
        record = POP3Record(host=host, port=port)
        record.protocol = "POP3S" if use_ssl else "POP3"
        
        # Check capability cache first
        capabilities_cache_key = CacheKeys.pop3_capabilities(f"{host}:{port}")
        cached_capabilities = cache_manager.get(capabilities_cache_key)
        
        if cached_capabilities:
            logger.debug(f"[{trace_id}] Cache hit for POP3 capabilities: {host}:{port}")
            record.capabilities = cached_capabilities.get('capabilities', [])
            record.supports_starttls = cached_capabilities.get('supports_starttls', False)
            record.supports_user_pass = cached_capabilities.get('supports_user_pass', False)
            record.supports_apop = cached_capabilities.get('supports_apop', False)
            record.supports_oauth = cached_capabilities.get('supports_oauth', False)
            record.supports_top = cached_capabilities.get('supports_top', False)
            record.supports_uidl = cached_capabilities.get('supports_uidl', False)
            record.banner = cached_capabilities.get('banner', '')
            record.secure_connection = use_ssl
            record.success = True
            return record
        
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            if use_ssl:
                # Direct SSL connection (port 995)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
                record.secure_connection = True
            
            # Connect to server
            sock.connect((host, port))
            
            # Read welcome banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            record.banner = banner
            
            # Check if server responds with +OK
            if not banner.startswith('+OK'):
                record.error = f"Invalid POP3 response: {banner}"
                sock.close()
                return record
            
            # Send CAPA command to get capabilities
            sock.send(b'CAPA\r\n')
            response = self._read_pop3_response(sock)
            
            if response.startswith('+OK'):
                # Parse capabilities
                capabilities = []
                lines = response.split('\n')[1:]  # Skip first +OK line
                
                for line in lines:
                    line = line.strip()
                    if line == '.':  # End of capabilities
                        break
                    if line:
                        capabilities.append(line)
                
                record.capabilities = capabilities
                
                # Check for specific capabilities
                for cap in capabilities:
                    cap_upper = cap.upper()
                    if 'STLS' in cap_upper or 'STARTTLS' in cap_upper:
                        record.supports_starttls = True
                    elif 'USER' in cap_upper:
                        record.supports_user_pass = True
                    elif 'APOP' in cap_upper:
                        record.supports_apop = True
                    elif 'OAUTH' in cap_upper or 'XOAUTH' in cap_upper:
                        record.supports_oauth = True
                    elif 'TOP' in cap_upper:
                        record.supports_top = True
                    elif 'UIDL' in cap_upper:
                        record.supports_uidl = True
                
                record.success = True
                logger.debug(f"[{trace_id}] POP3 capabilities for {host}:{port}: {capabilities}")
            
            else:
                # CAPA not supported, try basic connection test
                record.success = True
                record.supports_user_pass = True  # Assume basic USER/PASS support
                logger.debug(f"[{trace_id}] POP3 server {host}:{port} doesn't support CAPA")
            
            # Test STARTTLS if on port 110 and not already SSL
            if not use_ssl and port == 110 and not record.supports_starttls:
                sock.send(b'STLS\r\n')
                stls_response = self._read_pop3_response(sock)
                if stls_response.startswith('+OK'):
                    record.supports_starttls = True
                    logger.debug(f"[{trace_id}] STARTTLS supported on {host}:110")
            
            sock.close()
            
            # Cache the capabilities
            try:
                capabilities_data = {
                    'capabilities': record.capabilities,
                    'supports_starttls': record.supports_starttls,
                    'supports_user_pass': record.supports_user_pass,
                    'supports_apop': record.supports_apop,
                    'supports_oauth': record.supports_oauth,
                    'supports_top': record.supports_top,
                    'supports_uidl': record.supports_uidl,
                    'banner': record.banner,
                    'cached_at': now_utc().isoformat()
                }
                
                cache_ttl = self.rate_limit_manager.get_pop3_capabilities_cache_ttl()
                cache_manager.set(capabilities_cache_key, capabilities_data, ttl=cache_ttl)
                logger.debug(f"[{trace_id}] Cached POP3 capabilities for {host}:{port}")
                
            except Exception as cache_error:
                logger.error(f"[{trace_id}] Failed to get cache TTL from database for POP3 capabilities: {cache_error}")
                # Don't cache if we can't get TTL from database
            
        except socket.timeout:
            record.error = "Connection timeout"
            logger.debug(f"[{trace_id}] POP3 connection timeout: {host}:{port}")
        except socket.gaierror as e:
            record.error = f"DNS resolution failed: {str(e)}"
            logger.debug(f"[{trace_id}] POP3 DNS error for {host}: {e}")
        except ConnectionRefusedError:
            record.error = "Connection refused"
            logger.debug(f"[{trace_id}] POP3 connection refused: {host}:{port}")
        except ssl.SSLError as e:
            record.error = f"SSL error: {str(e)}"
            logger.debug(f"[{trace_id}] POP3 SSL error for {host}:{port}: {e}")
        except Exception as e:
            record.error = f"Connection error: {str(e)}"
            logger.debug(f"[{trace_id}] POP3 connection error for {host}:{port}: {e}")
        
        return record
    
    def _read_pop3_response(self, sock: socket.socket, max_lines: int = 50) -> str:
        """Read POP3 multi-line response"""
        response_lines = []
        line_count = 0
        
        while line_count < max_lines:
            try:
                line = sock.recv(1024).decode('utf-8', errors='ignore')
                if not line:
                    break
                
                response_lines.append(line)
                
                # Check if we have the end marker
                if '\r\n.\r\n' in line or '\n.\n' in line:
                    break
                    
                line_count += 1
                
            except socket.timeout:
                break
            except Exception:
                break
        
        return ''.join(response_lines)
    
    def _assess_security_level(self, result: POP3Result) -> str:
        """Assess the security level based on available features"""
        if result.supports_ssl and result.supports_oauth:
            return "excellent"
        elif result.supports_ssl and result.supports_starttls:
            return "good"
        elif result.supports_ssl or result.supports_starttls:
            return "moderate"
        elif result.has_pop3:
            return "basic"
        else:
            return "none"
    
    def _generate_recommendations(self, result: POP3Result) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not result.has_pop3:
            recommendations.append("Consider enabling POP3 access for legacy email clients")
            return recommendations
        
        if not result.supports_ssl:
            recommendations.append("Enable POP3S (port 995) for secure connections")
        
        if not result.supports_starttls:
            recommendations.append("Enable STARTTLS support on port 110")
        
        if not result.supports_oauth:
            recommendations.append("Consider implementing OAuth2 authentication")
        
        if result.security_level in ["basic", "moderate"]:
            recommendations.append("Upgrade to modern authentication methods")
        
        # Check if only insecure options are available
        insecure_only = all(
            not server.secure_connection and not server.supports_starttls 
            for server in result.pop3_servers
        )
        
        if insecure_only:
            recommendations.append("WARNING: Only insecure POP3 connections available")
        
        return recommendations

    def _record_pop3_statistics(self, result: POP3Result, dns_lookups: int = 1):
        """Record POP3 validation statistics"""
        try:
            stats_manager = DNSServerStats()
            
            # Convert recommendations and errors to strings for database storage
            errors_str = result.error if result.error else None
            
            stats_manager.record_pop3_statistics(
                trace_id=result.trace_id,
                domain=result.domain,
                has_pop3=result.has_pop3,
                servers_found=len(result.pop3_servers),
                security_level=result.security_level,
                supports_ssl=result.supports_ssl,
                supports_starttls=result.supports_starttls,
                supports_oauth=result.supports_oauth,
                dns_lookups=dns_lookups,
                processing_time_ms=result.duration_ms,
                errors=errors_str
            )
            
            # Also store detailed analysis
            pop3_analysis_data = {
                'has_pop3': result.has_pop3,
                'servers_found': len(result.pop3_servers),
                'security_level': result.security_level,
                'supports_ssl': result.supports_ssl,
                'supports_starttls': result.supports_starttls,
                'supports_oauth': result.supports_oauth,
                'dns_lookups': dns_lookups,
                'execution_time_ms': result.duration_ms,
                'errors': [result.error] if result.error else [],
                'warnings': [],
                'recommendations': result.recommendations,
                'servers': [
                    {
                        'host': server.host,
                        'port': server.port,
                        'protocol': server.protocol,
                        'secure': server.secure_connection,
                        'capabilities': server.capabilities
                    } for server in result.pop3_servers
                ]
            }
            
            stats_manager.store_pop3_analysis(result.domain, pop3_analysis_data, result.trace_id)
            
            logger.debug(f"[{result.trace_id}] POP3 statistics recorded for {result.domain}")
            
        except Exception as e:
            logger.warning(f"[{result.trace_id}] Failed to record POP3 statistics: {e}")

@trace_function("pop3_check")
def pop3_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """Main POP3 check function called by the engine"""
    # Ensure context has valid trace_id
    context = ensure_context_has_trace_id(context)
    trace_id = context['trace_id']
    
    email = context.get("email", "")
    
    if not email or '@' not in email:
        return {
            "status": "error",
            "error": "Invalid email format",
            "pop3_details": {},
            "has_pop3": False
        }
    
    # Extract domain
    domain = email.split('@')[1].strip().lower()
    
    try:
        # Initialize verifier and check POP3
        with EnhancedOperationTimer("pop3_check_total", metadata={"domain": domain, "email": email}) as timer:
            verifier = POP3Verifier()
            result = verifier.check_pop3(domain, trace_id)
        
        # Format response for the engine
        return {
            "status": "success" if result.has_pop3 else "no_pop3",
            "error": result.error,
            "has_pop3": result.has_pop3,
            "pop3_servers": [
                {
                    "host": server.host,
                    "port": server.port,
                    "protocol": server.protocol,
                    "secure": server.secure_connection,
                    "capabilities": server.capabilities,
                    "supports_starttls": server.supports_starttls,
                    "supports_oauth": server.supports_oauth,
                    "supports_user_pass": server.supports_user_pass,
                    "supports_apop": server.supports_apop,
                    "supports_top": server.supports_top,
                    "supports_uidl": server.supports_uidl,
                    "banner": server.banner
                } for server in result.pop3_servers
            ],
            "security_level": result.security_level,
            "supports_ssl": result.supports_ssl,
            "supports_starttls": result.supports_starttls,
            "supports_oauth": result.supports_oauth,
            "recommendations": result.recommendations,
            "servers_checked": result.servers_checked,
            "duration_ms": result.duration_ms,
            "execution_time": timer.elapsed_ms
        }
        
    except Exception as e:
        logger.error(f"[{trace_id}] POP3 check failed for {email}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "pop3_details": {},
            "has_pop3": False
        }