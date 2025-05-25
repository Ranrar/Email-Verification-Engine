"""
Email Verification Engine
=====================
SMTP validation module

This module verifies mailbox existence via SMTP connection by:
1. Connecting to MX servers
2. Using SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO) to verify the existence of the mailbox
3. Handling different response codes
4. Implementing rate limiting and caching

The module respects privacy and does not send actual emails.
"""

import socket
import ssl
import time
import re
import threading
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone, timedelta

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.time import EnhancedOperationTimer
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager, rate_limit_manager
from src.managers.port import PortManager, port_manager
from src.managers.log import Axe
from src.helpers.dbh import sync_db

# Initialize logging
logger = Axe()

# Global rate limiter for SMTP connections
_rate_limiter_lock = threading.Lock()
_domain_last_connection = {}

class SMTPValidator:
    """SMTP validator to verify mailbox existence"""
    
    def __init__(self, test_mode=False):
        """Initialize with required managers and settings"""
        # Use the singleton instances
        self.dns_manager = DNSManager()
        self.rate_limit_manager = rate_limit_manager
        self.port_manager = port_manager
        self.test_mode = test_mode
        
        # Load rate limit settings
        self.max_connections_per_domain = self.rate_limit_manager.get_max_connections_per_domain()
        self.connect_timeout = self.rate_limit_manager.get_connect_timeout()
        self.read_timeout = self.rate_limit_manager.get_read_timeout()
        self.max_retries = self.rate_limit_manager.get_max_retries()
        
        # Cache TTLs
        self.cache_ttl = self.rate_limit_manager.get_cache_limit('cache_duration_smtp_result')
        
        # SMTP ports to try, in order of priority
        self.smtp_ports = self._get_smtp_ports()
        
        logger.debug(f"SMTPValidator initialized with connect_timeout={self.connect_timeout}s, "
                    f"read_timeout={self.read_timeout}s, max_retries={self.max_retries}")
    
    def _get_smtp_ports(self) -> List[Dict[str, Any]]:
        """Get SMTP ports from the port manager in priority order"""
        try:
            # Use port manager instead of direct database access
            ports = self.port_manager.get_enabled_smtp_ports()
            
            if ports:
                return ports
            
            logger.warning("No SMTP ports found in port manager, using defaults")
        except Exception as e:
            logger.warning(f"Failed to get SMTP ports from port manager: {e}")
    
        # Use hardcoded defaults as a last resort
        return [
            {"port": 587, "description": "Encryption with STARTTLS, client-to-server (recommended)", "priority": 1, "enabled": True},
            {"port": 465, "description": "Encryption with SSL/TLS, client-to-server (legacy support)", "priority": 2, "enabled": True},
            {"port": 25, "description": "No encryption, None/TLS, server-to-server (relay)", "priority": 3, "enabled": True}
        ]
    
    def verify_email(self, email: str, domain: str, mx_servers: List[Dict[str, Any]], 
                    sender_email: Optional[str] = None, trace_id: Optional[str] = None) -> Dict[str, Any]:
        """Verify if an email exists by checking the SMTP server"""
        if not mx_servers:
            logger.info(f"[{trace_id}] No MX servers for {domain}")
            return {
                "valid": False,
                "error": "No MX servers available",
                "is_deliverable": False,
                "details": {}
            }
        
        # Check if domain is in exponential backoff period
        if not self.test_mode:  # Skip this check in test mode
            retry_available, retry_time = self._check_retry_availability(domain)
            if not retry_available:
                # Fix: Add null check before subtraction
                wait_seconds = 0
                if retry_time is not None:
                    wait_seconds = int((retry_time - datetime.now(timezone.utc)).total_seconds())
                retry_time_str = retry_time.strftime("%Y-%m-%d %H:%M:%S UTC") if retry_time else "unknown"
                
                logger.warning(f"[{trace_id}] Domain {domain} in backoff period. Retry after: {retry_time_str}")
                return {
                    "valid": False,
                    "error": f"Domain in exponential backoff period",
                    "is_deliverable": False,
                    "details": {
                        "in_backoff": True,
                        "retry_after": retry_time_str,
                        "wait_seconds": wait_seconds,
                        "backoff_reason": "Previous connection failures"
                    }
                }
        
        # Check rate limits for domain
        if not self._check_domain_rate_limit(domain):
            logger.warning(f"[{trace_id}] Rate limit exceeded for {domain}")
            return {
                "valid": False,
                "error": "Rate limit exceeded for domain",
                "is_deliverable": False,
                "details": {"rate_limited": True}
            }
        
        # Set default sender address if not provided
        if not sender_email:
            sender_email = f"verification@example.com"
        
        # Track overall result
        result = {
            "valid": False,
            "is_deliverable": False,
            "details": {
                "mx_servers_tried": 0,
                "ports_tried": 0,
                "connection_success": False,
                "smtp_banner": "",
                "supports_starttls": False,
                "supports_auth": False,
                "vrfy_supported": False,
                "errors": [],
                "smtp_flow_success": False,
                "server_message": ""
            }
        }
        
        # Try each MX server until successful or all failed
        mx_servers_tried = 0
        for mx in mx_servers:
            mx_host = mx.get('exchange', "")
            if not mx_host:
                continue
                
            mx_servers_tried += 1
            logger.debug(f"[{trace_id}] Trying MX server {mx_host} for {email}")
            
            # Try each port until successful or all failed
            success, details = self._try_smtp_ports(mx_host, email, domain, sender_email, trace_id)
            
            # Update result with details
            result["details"]["mx_servers_tried"] = mx_servers_tried
            result["details"]["ports_tried"] = details.get("ports_tried", 0)
            result["details"].update(details)
            
            if success:
                result["valid"] = True
                result["is_deliverable"] = True
                logger.info(f"[{trace_id}] Email {email} is valid via {mx_host}")
                break
        
        # Record the email checking result if at least one server was tried
        if mx_servers_tried > 0:
            if not result["valid"]:
                result["error"] = "All SMTP servers rejected the address"
            
            # Update for better context
            if result["details"].get("smtp_error_code") == 550:
                result["error"] = "Mailbox does not exist"
            elif result["details"].get("smtp_error_code") == 552:
                result["error"] = "Mailbox full"
            elif result["details"].get("smtp_error_code") == 553:
                result["error"] = "Mailbox name not allowed"
        
        return result
            
    def _try_smtp_ports(self, mx_host: str, email: str, domain: str, 
                       sender_email: str, trace_id: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
        """
        Try connecting to different SMTP ports of an MX server
        
        Args:
            mx_host: MX server hostname
            email: Email to verify
            domain: Domain part of email
            sender_email: Email to use as sender
            trace_id: Optional trace ID for logging
            
        Returns:
            Tuple of (success, details_dict)
        """
        details = {
            "ports_tried": 0,
            "connection_success": False,
            "smtp_banner": "",
            "supports_starttls": False,
            "supports_auth": False,
            "port": None,
            "errors": []
        }
        
        for port_info in self.smtp_ports:
            port = port_info["port"]
            details["ports_tried"] += 1
            
            logger.debug(f"[{trace_id}] Trying {mx_host}:{port} for {email}")
            
            # Try to connect with appropriate SSL/TLS setting based on port
            use_ssl = (port == 465)
            success, port_details = self._verify_with_smtp_connection(
                mx_host, port, email, domain, sender_email, use_ssl, trace_id
            )
            
            # Update details with this port's results
            details.update(port_details)
            details["port"] = port
            
            if success:
                logger.debug(f"[{trace_id}] Successfully verified {email} via {mx_host}:{port}")
                return True, details
        
        logger.debug(f"[{trace_id}] Failed to verify {email} on all ports of {mx_host}")
        return False, details
    
    def _verify_with_smtp_connection(self, mx_host: str, port: int, email: str, domain: str, 
                                   sender_email: str, use_ssl: bool, trace_id: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
        """Connect to an SMTP server and verify email address"""
        details = {
            "connection_success": False,
            "smtp_banner": "",
            "supports_starttls": False,
            "supports_auth": False,
            "vrfy_supported": False,
            "smtp_flow_success": False,
            "server_message": "",
            "errors": []
        }
        
        # Get adaptive timeouts for this domain
        connect_timeout, read_timeout = self._get_adaptive_timeout(domain)
        
        # Track response time
        start_time = time.time()
        response_time_ms = 0
        
        sock = None
        try:
            # Create socket connection with adaptive timeout
            with EnhancedOperationTimer("smtp_connect", {"host": mx_host, "port": port}) as timer:
                sock = socket.create_connection((mx_host, port), timeout=connect_timeout)
                
                # Wrap with SSL if needed
                if use_ssl:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=mx_host)
                
                # Set adaptive read timeout
                sock.settimeout(read_timeout)
                
                # Record success
                details["connection_success"] = True
                logger.debug(f"[{trace_id}] Connected to {mx_host}:{port} with adaptive timeouts (c:{connect_timeout:.1f}s, r:{read_timeout:.1f}s)")
        
            # Receive banner
            banner = self._receive_response(sock)
            details["smtp_banner"] = banner.replace('\n', ' ').replace('\r', '')
            logger.debug(f"[{trace_id}] Banner: {details['smtp_banner']}")
            
            # Send EHLO
            self._send_command(sock, f"EHLO {domain}")
            ehlo_response = self._receive_response(sock)
            
            # Check capabilities from EHLO response
            details["supports_starttls"] = "STARTTLS" in ehlo_response
            details["supports_auth"] = "AUTH" in ehlo_response
            details["vrfy_supported"] = "VRFY" in ehlo_response
            
            # Try STARTTLS if supported and not already using SSL
            if details["supports_starttls"] and not use_ssl:
                self._send_command(sock, "STARTTLS")
                starttls_response = self._receive_response(sock)
                if starttls_response.startswith("220"):
                    # Upgrade to TLS
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=mx_host)
                    
                    # Need to send EHLO again after STARTTLS
                    self._send_command(sock, f"EHLO {domain}")
                    self._receive_response(sock)
            
            # Mail from
            from_cmd = f"MAIL FROM:<{sender_email}>"
            self._send_command(sock, from_cmd)
            mail_from_response = self._receive_response(sock)
            
            if not mail_from_response.startswith("250"):
                details["errors"].append(f"MAIL FROM error: {mail_from_response}")
                return False, details
            
            # RCPT TO
            rcpt_cmd = f"RCPT TO:<{email}>"
            self._send_command(sock, rcpt_cmd)
            rcpt_response = self._receive_response(sock)
            
            # Save the full message for analysis
            details["server_message"] = rcpt_response
            
            # Extract SMTP code
            smtp_code_match = re.match(r"^(\d+)", rcpt_response)
            if smtp_code_match:
                details["smtp_error_code"] = int(smtp_code_match.group(1))
            
            # Mark as success if SMTP code starts with 250
            success = rcpt_response.startswith("250")
            details["smtp_flow_success"] = success
            
            # Update statistics with result
            error_type = None
            error_code = details.get("smtp_error_code")
            if not success and error_code:
                # Classify error type for proper handling
                if 400 <= error_code < 500:
                    error_type = 'temporary'
                elif 500 <= error_code < 600:
                    error_type = 'permanent'
            
            # Update call parameters for _update_domain_stats
            self._update_domain_stats(
                domain, 
                success, 
                response_time_ms, 
                error_code=error_code,
                error_type=error_type,
                trace_id=trace_id,
                mx_host=mx_host,  
                port=port         
            )
            
            return success, details
            
        except socket.timeout as e:
            error_msg = f"Timeout during SMTP connection to {mx_host}:{port}: {str(e)}"
            logger.warning(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            details["timeout_detected"] = True
            
            # Update statistics specifically for timeout
            self._update_domain_stats(
                domain, 
                False, 
                int((time.time() - start_time) * 1000),
                error_type='timeout',
                trace_id=trace_id,
                mx_host=mx_host,  # Pass mx_host here
                port=port         # Pass port here
            )
            
            # Add domain to temporary blocklist
            self._add_to_temporary_blocklist(domain, "SMTP timeout", trace_id)
            
            return False, details
        
        except (socket.gaierror, socket.error, ssl.SSLError) as e:
            error_msg = f"SMTP connection error to {mx_host}:{port}: {str(e)}"
            logger.debug(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            return False, details
        
        except Exception as e:
            error_msg = f"Unexpected error during SMTP validation of {email}: {str(e)}"
            logger.warning(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            return False, details
            
        finally:
            # Ensure socket is closed
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _send_command(self, sock: socket.socket, command: str) -> None:
        """Send an SMTP command to the server"""
        sock.sendall(f"{command}\r\n".encode())
    
    def _receive_response(self, sock: socket.socket) -> str:
        """Receive and return SMTP server response"""
        response = []
        while True:
            line = sock.recv(1024).decode('utf-8', errors='ignore')
            if not line:
                break
            response.append(line)
            # If the 4th character is a space, we've reached the last line
            if len(line) > 3 and line[3] == ' ':
                break
        
        return ''.join(response)
    
    def _check_domain_rate_limit(self, domain: str) -> bool:
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
                min_interval = self.rate_limit_manager.get_smtp_port25_conn_interval()
                
                if time_diff < min_interval:
                    # Add to temporary blocklist with rate limit reason when repeatedly hit
                    # But only if this is not the first rate limit hit
                    if hasattr(self, '_rate_limit_hits') and domain in self._rate_limit_hits:
                        self._rate_limit_hits[domain] += 1
                        # If hit rate limits multiple times, add to temporary blocklist
                        if self._rate_limit_hits[domain] >= 3:  # After 3 hits
                            self._add_to_temporary_blocklist(
                                domain, 
                                f"Rate limit exceeded ({self._rate_limit_hits[domain]} attempts)", 
                                None
                            )
                            # Reset counter
                            self._rate_limit_hits[domain] = 0
                    else:
                        # Initialize rate limit hits tracking
                        if not hasattr(self, '_rate_limit_hits'):
                            self._rate_limit_hits = {}
                        self._rate_limit_hits[domain] = 1
                    
                    # Send notification about rate limit
                    from src.utils.notifier import Notifier
                    notify = Notifier()
                    notify.info(
                        f"Rate limit applied for {domain}",
                        f"Minimum interval between checks: {min_interval} seconds")
                    
                    return False
        
            # Update last connection time
            _domain_last_connection[domain] = current_time
            
            # Use the rate limit manager's check_rate_limit method
            allowed, limit_info = self.rate_limit_manager.check_rate_limit(
                'smtp', domain, 'max_connections_per_domain')
            
            if not allowed:
                # If rate limited by global settings, notify
                from src.utils.notifier import Notifier
                notify = Notifier()
                
                # Fix: Make limit_info checks more robust
                limit_value = "unknown"
                period_value = "period"
                if isinstance(limit_info, dict):
                    limit_value = limit_info.get('limit', "unknown")
                    period_value = limit_info.get('period', "period")
                
                notify.warning(
                    f"Rate limit exceeded for {domain}",
                    f"Maximum connection limit reached: {limit_value} per {period_value}")
            
            return allowed
    
    def _add_to_temporary_blocklist(self, domain: str, reason: str, trace_id: Optional[str] = None) -> None:
        """
        Add a domain to the temporary blocklist due to timeouts or rate limiting
        """
        try:
            # Import here to avoid circular imports
            from src.helpers.dbh import sync_db
            from src.managers.time import now_utc
            
            # Calculate block duration based on reason
            try:
                if "timeout" in reason.lower():
                    block_seconds = self.rate_limit_manager.get_smtp_limit('timeout_block_duration')
                    if block_seconds is None:
                        block_seconds = 600  # 10 minutes default
                else:
                    block_seconds = self.rate_limit_manager.get_smtp_limit('rate_limit_block_duration')
                    if block_seconds is None:
                        block_seconds = 300  # 5 minutes default
            except KeyError:
                block_seconds = 600 if "timeout" in reason.lower() else 300
            
            # Current time
            current_time = now_utc()
            # Calculate expiry time
            from datetime import timedelta
            expiry_time = current_time + timedelta(seconds=block_seconds)
            
            # Get current stats
            stats = self._get_domain_stats(domain)
            
            # Calculate new backoff level (use current or set to 1)
            current_backoff_level = stats.get('current_backoff_level', 0) or 0
            new_backoff_level = current_backoff_level + 1
            
            # Update domain stats to block it
            sync_db.execute(
                """
                UPDATE smtp_domain_stats 
                SET 
                    consecutive_failures = consecutive_failures + 1,
                    current_backoff_level = $1,
                    retry_available_after = $2,
                    timeout_adjustment_factor = CASE 
                        WHEN $3 LIKE '%timeout%' 
                        THEN LEAST((timeout_adjustment_factor * 1.2), 3.0)
                        ELSE timeout_adjustment_factor
                    END,
                    last_updated_at = $4,
                    last_failure_at = $5,
                    is_problematic = TRUE
                WHERE domain = $6
                """,
                new_backoff_level, expiry_time, reason, current_time, current_time, domain
            )
            
            logger.info(f"[{trace_id}] Added {domain} to temporary blocklist for {block_seconds} seconds. Reason: {reason}")
            
            # Send notification
            from src.utils.notifier import Notifier
            notify = Notifier()
            notify.warning(
                f"Domain {domain} temporarily blocked", 
                f"Reason: {reason}. Will retry in {block_seconds} seconds.")
            
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to add {domain} to temporary blocklist: {e}")

    def _get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Get domain statistics and settings from database using UPSERT pattern"""
        try:
            # Use a single query with INSERT ... ON CONFLICT DO NOTHING
            sync_db.execute(
                """
                INSERT INTO smtp_domain_stats (domain)
                VALUES ($1)
                ON CONFLICT (domain) DO NOTHING
                """,
                domain
            )
            
            # Now get the record which will definitely exist
            result = sync_db.fetchrow(
                """
                SELECT * FROM smtp_domain_stats 
                WHERE domain = $1
                """, 
                domain
            )
            
            return result or {}
        except Exception as e:
            logger.warning(f"Failed to get domain stats for {domain}: {e}")
            return {}

    def _update_domain_stats(self, domain: str, success: bool, 
                          response_time_ms: int = 0, error_code: Optional[int] = None,
                          error_type: Optional[str] = None, trace_id: Optional[str] = None,
                          mx_host: Optional[str] = None, port: Optional[int] = None):
        """Update domain statistics after an attempt"""
        try:
            current_time = datetime.now(timezone.utc)
            
            if success:
                # Update stats for successful attempt
                sync_db.execute(
                    """
                    UPDATE smtp_domain_stats 
                    SET 
                        total_attempts = total_attempts + 1,
                        successful_attempts = successful_attempts + 1,
                        success_rate = (successful_attempts + 1)::numeric / (total_attempts + 1),
                        avg_response_time_ms = CASE 
                            WHEN successful_attempts > 0 
                            THEN ((avg_response_time_ms * successful_attempts) + $1) / (successful_attempts + 1)
                            ELSE $2
                        END,
                        min_response_time_ms = CASE 
                            WHEN min_response_time_ms = 0 OR $3 < min_response_time_ms THEN $4
                            ELSE min_response_time_ms 
                        END,
                        max_response_time_ms = CASE 
                            WHEN max_response_time_ms < $5 THEN $6
                            ELSE max_response_time_ms 
                        END,
                        consecutive_failures = 0,
                        current_backoff_level = 0,
                        last_updated_at = $7,
                        last_success_at = $8
                    WHERE domain = $9
                    """,
                    response_time_ms, response_time_ms, response_time_ms, response_time_ms, 
                    response_time_ms, response_time_ms, current_time, current_time, domain
                )
            else:
                # Get current stats
                stats = self._get_domain_stats(domain)
                consecutive_failures = (stats.get('consecutive_failures', 0) or 0) + 1
                current_backoff_level = stats.get('current_backoff_level', 0) or 0
                
                # Implement exponential backoff for temporary failures
                if error_type == 'timeout' or (error_code and error_code in (421, 450, 451, 452)):
                    # Increase backoff level for temporary errors (max level 10)
                    new_backoff_level = min(current_backoff_level + 1, 10)
                    # Calculate backoff time using exponential formula (2^level seconds), max 24h
                    backoff_seconds = min(2 ** new_backoff_level, 86400)
                    retry_available_after = current_time + timedelta(seconds=backoff_seconds)
                    
                    # Update timeout adjustment factor (for adaptive timing)
                    timeout_adjustment = min(stats.get('timeout_adjustment_factor', 1.0) or 1.0 * 1.2, 3.0)
                else:
                    new_backoff_level = current_backoff_level
                    retry_available_after = None
                    timeout_adjustment = stats.get('timeout_adjustment_factor', 1.0) or 1.0
                
                # Mark domain as problematic if it fails consistently
                is_problematic = consecutive_failures >= 5
                
                # Update stats for failed attempt
                sync_db.execute(
                    """
                    UPDATE smtp_domain_stats 
                    SET 
                        total_attempts = total_attempts + 1,
                        failed_attempts = failed_attempts + 1,
                        timeout_count = CASE WHEN $1 = 'timeout' THEN timeout_count + 1 ELSE timeout_count END,
                        success_rate = successful_attempts::numeric / (total_attempts + 1),
                        consecutive_failures = $2,
                        current_backoff_level = $3,
                        retry_available_after = $4,
                        timeout_adjustment_factor = $5,
                        last_updated_at = $6,
                        last_failure_at = $7,
                        is_problematic = $8
                    WHERE domain = $9
                    """,
                    error_type, consecutive_failures, new_backoff_level, retry_available_after, 
                    timeout_adjustment, current_time, current_time, is_problematic, domain
                )
            
            # Record attempt history
            sync_db.execute(
                """
                INSERT INTO smtp_domain_attempt_history
                (domain, email, mx_host, port, attempt_time, response_time_ms, success, 
                error_code, error_type, trace_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                domain, '', mx_host or '', port or 0, current_time, response_time_ms, 
                success, error_code, error_type, trace_id
            )
            
        except Exception as e:
            logger.warning(f"Failed to update domain stats for {domain}: {e}")

    def _get_adaptive_timeout(self, domain: str) -> Tuple[float, float]:
        """Get adaptive timeouts based on domain performance history"""
        try:
            stats = self._get_domain_stats(domain)
            if not stats:
                return self.connect_timeout, self.read_timeout
            
            # Base timeouts (either from regional settings or defaults)
            connect_timeout = self.connect_timeout
            read_timeout = self.read_timeout
            
            # Apply timeout adjustment factor from domain stats - Convert Decimal to float
            adjustment_factor = float(stats.get('timeout_adjustment_factor', 1.0) or 1.0)
            connect_timeout *= adjustment_factor
            read_timeout *= adjustment_factor
            
            # Use response time data for intelligent adjustments if we have enough data
            avg_response_time_ms = stats.get('avg_response_time_ms')
            if avg_response_time_ms is not None and stats.get('successful_attempts', 0) > 5:
                avg_time_sec = avg_response_time_ms / 1000.0
                if avg_time_sec > 1.0:
                    # Adjust read timeout based on average response time (plus buffer)
                    read_timeout = max(read_timeout, min(avg_time_sec * 1.5, 120.0))
            
            # Apply reasonable limits
            return min(connect_timeout, 30.0), min(read_timeout, 120.0)
            
        except Exception as e:
            logger.warning(f"Error calculating adaptive timeouts for {domain}: {e}")
            return self.connect_timeout, self.read_timeout

    def _check_retry_availability(self, domain: str) -> Tuple[bool, Optional[datetime]]:
        """Check if domain is available for retry based on backoff settings"""
        try:
            stats = self._get_domain_stats(domain)
            retry_after = stats.get('retry_available_after')
            
            if not retry_after:
                return True, None
                
            now = datetime.now(timezone.utc)
            if now < retry_after:
                return False, retry_after
                
            return True, None
            
        except Exception as e:
            logger.warning(f"Error checking retry availability for {domain}: {e}")
            return True, None

    def _update_geographic_info(self, domain: str, country_code=None, region=None, provider=None):
        """Update geographic information for a domain"""
        if not (country_code or region or provider):
            return
        
        try:
            updates = []
            params = []
            param_index = 1  # Start with $1
            
            if country_code:
                updates.append(f"country_code = ${param_index}")
                params.append(country_code)
                param_index += 1
                
            if region:
                updates.append(f"region = ${param_index}")
                params.append(region)
                param_index += 1
                
            if provider:
                updates.append(f"detected_provider = ${param_index}")
                params.append(provider)
                param_index += 1
                
            if updates:
                params.append(domain)
                sync_db.execute(
                    f"""
                    UPDATE smtp_domain_stats 
                    SET {", ".join(updates)}
                    WHERE domain = ${param_index}
                    """,
                    *params  # Unpack the params with * operator
                )
        except Exception as e:
            logger.warning(f"Failed to update geographic info for {domain}: {e}")

def validate_email(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates an email address by checking SMTP server responses.
    
    Args:
        context: Dictionary containing email and validation context
            - email: Email address to validate
            - trace_id: Optional trace ID for tracking
            - mx_records: Optional MX records (if already retrieved)
            - test_mode: Optional boolean to bypass rate limits for testing
            
    Returns:
        Dict with validation results:
            - valid: Whether email passed validation
            - is_deliverable: Whether email appears deliverable
            - details: Dictionary with detailed information
    """
    email = context.get('email', '')
    trace_id = context.get('trace_id', '')
    test_mode = context.get('test_mode', False)
    
    logger.debug(f"[{trace_id}] Starting SMTP validation for {email}")
    
    # Parse email to get domain
    try:
        if '@' not in email:
            return {
                'valid': False,
                'error': 'Invalid email format',
                'is_deliverable': False,
                'details': {}
            }
        local_part, domain = email.rsplit('@', 1)
    except ValueError:
        return {
            'valid': False,
            'error': 'Invalid email format',
            'is_deliverable': False,
            'details': {}
        }
    
    # Create cache key
    cache_key = f"{CacheKeys.SMTP_RESULT}:{email}"  # Use SMTP_RESULT instead of SMTP_CHECK
    
    # Check cache
    cached_result = cache_manager.get(cache_key)
    if cached_result:
        logger.debug(f"[{trace_id}] Using cached SMTP validation result for {email}")
        return cached_result
    
    # Get MX records if not already in context
    mx_records = context.get('mx_records')
    if not mx_records:
        # Try to get from the context's validation results
        mx_result = context.get('mx_records_result')
        if mx_result and isinstance(mx_result, dict):
            mx_records = mx_result.get('records')
    
    # If still no MX records, we need to fetch them
    if not mx_records:
        logger.debug(f"[{trace_id}] No MX records in context for {domain}, fetching...")
        
        # Import here to avoid circular imports
        try:
            from src.engine.functions.mx import fetch_mx_records
            mx_result = fetch_mx_records(context)
            mx_records = mx_result.get('records', [])
            # Store the complete result in context for later geographic extraction
            context['mx_records_result'] = mx_result
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to fetch MX records for {domain}: {e}")
            return {
                'valid': False,
                'error': f"Failed to retrieve MX records: {str(e)}",
                'is_deliverable': False,
                'details': {}
            }
    
    # No MX records found
    if not mx_records:
        logger.info(f"[{trace_id}] No MX records found for {domain}")
        return {
            'valid': False,
            'error': 'No MX records found for domain',
            'is_deliverable': False,
            'details': {}
        }
    
    # Use configurable sender pattern instead of hardcoded domain
    try:
        sender_pattern = context.get('sender_pattern')
        if not sender_pattern:
            # Try to get from rate limit manager using smtp category
            sender_pattern = rate_limit_manager.get_smtp_limit('sender_pattern')
    except Exception:
        sender_pattern = None
        
    # If no configured pattern, fall back to a generic pattern
    if not sender_pattern:
        sender_pattern = "verification@{domain}"
        
    # Format the sender email with the appropriate domain
    sender_email = sender_pattern.format(
        domain=domain,
        local=local_part,
        random=f"verify{int(time.time())}"  # Include timestamp for uniqueness
    )
    
    # Initialize SMTP validator
    validator = SMTPValidator(test_mode=test_mode)
    
    # Extract and update geographic information from MX records
    if 'mx_records_result' in context and isinstance(context['mx_records_result'], dict):
        mx_result = context['mx_records_result']
        
        # Try to extract geographic data from MX infrastructure
        infra_info = mx_result.get('infrastructure_info', {})
        if infra_info:
            country_code = None
            region = None
            provider = None
            
            # Get primary country code
            if infra_info.get('countries') and len(infra_info['countries']) > 0:
                country_code = infra_info['countries'][0]
                
            # Get provider info
            if infra_info.get('providers') and len(infra_info['providers']) > 0:
                provider = infra_info['providers'][0]
            
            # Get region if available
            email_provider = mx_result.get('email_provider', {})
            if email_provider and email_provider.get('provider_name'):
                provider = email_provider.get('provider_name')
            
            # Update domain stats with this geographic info
            validator._update_geographic_info(domain, country_code, region, provider)
    
    # Perform validation
    with EnhancedOperationTimer("smtp_validation", {"email": email}) as timer:
        result = validator.verify_email(email, domain, mx_records, sender_email, trace_id)
    
    # Add execution time
    result['execution_time'] = timer.elapsed_ms
    
    # Cache result
    cache_manager.set(cache_key, result, ttl=validator.cache_ttl)
    
    logger.info(f"[{trace_id}] SMTP validation for {email}: {'✓ Valid' if result['valid'] else '✗ Invalid'}")
    
    return result