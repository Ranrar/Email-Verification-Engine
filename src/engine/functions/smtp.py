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
import traceback
import logging

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.time import EnhancedOperationTimer
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager
from src.managers.port import PortManager, port_manager
from src.managers.log import get_logger
from src.helpers.dbh import sync_db

# Import our refactored modules
from src.engine.functions.statistics import DomainStats
from src.engine.functions.whois import DomainInfoExtractor

# Initialize logging
logger = get_logger()

# Global rate limiter for SMTP connections
_rate_limiter_lock = threading.Lock()
_domain_last_connection = {}

class SMTPValidator:
    """SMTP validator to verify mailbox existence"""
    
    def __init__(self, test_mode=False):
        """Initialize with required managers and settings"""
        # Use the singleton instances
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
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
        
        # Create instances of our refactored classes
        self.stats_manager = DomainStats()
        self.domain_info = DomainInfoExtractor()
        
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
            # Fall back to empty list or raise an error if no ports found
            return []
        except Exception as e:
            error_msg = f"Database error: Failed to get SMTP ports from port manager: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
    
    def verify_email(self, email: str, domain: str, mx_servers: List[Dict[str, Any]], 
                 sender_email: Optional[str] = None, trace_id: Optional[str] = None,
                 context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Verify if an email exists by checking the SMTP server"""
        # Add overall timeout
        overall_timeout = self.rate_limit_manager.get_overall_timeout()
        start_time = time.time()
        
        # Context might be None when called directly from validate_smtp_batch
        context = context or {}
        
        # Throughout method, check if elapsed > overall_timeout:
        if time.time() - start_time > overall_timeout:
            return {"valid": False, "error": "Operation timed out", "is_deliverable": False, "details": {}}
        
        if not mx_servers:
            logger.info(f"[{trace_id}] No MX servers for {domain}")
            return {
                "valid": False,
                "error": "No MX servers available",
                "is_deliverable": False,
                "details": {}
            }
        
        # Get the BW result from context instead of making a separate call
        domain_whitelisted = False
        bw_result = context.get('bw_result', {})
        domain_whitelisted = bw_result.get('whitelisted', False)
        
        # If we don't have bw_result in context, fall back to direct check
        if not bw_result and not domain_whitelisted:
            try:
                from src.engine.functions.bw import get_domain_status
                domain_status = get_domain_status(domain)
                domain_whitelisted = domain_status.get('whitelisted', False)
                if domain_whitelisted:
                    logger.info(f"[{trace_id}] Domain {domain} is whitelisted, skipping temporary block check")
            except Exception as e:
                logger.debug(f"[{trace_id}] Could not check whitelist status: {e}")
        elif domain_whitelisted:
            logger.info(f"[{trace_id}] Using previously determined whitelist status for {domain}")
        
        # Check temporary blocklist unless domain is whitelisted
        if not domain_whitelisted and self._is_domain_temporarily_blocked(domain, trace_id):
            logger.info(f"[{trace_id}] Domain {domain} is temporarily blocked")
            return {
                "valid": False,
                "error": "Domain temporarily blocked due to previous issues",
                "is_deliverable": False,
                "details": {"temporarily_blocked": True}
            }
        
        # Check if domain is in exponential backoff period
        if not self.test_mode:
            retry_available, retry_time = self._check_retry_availability(domain)
            if not retry_available:
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
        # Use a default port (e.g., 25) for rate limit check at this stage
        if not self._check_domain_rate_limit(domain, 25, trace_id):
            logger.warning(f"[{trace_id}] Rate limit exceeded for {domain}")
            return {
                "valid": False,
                "error": "Rate limit exceeded for domain",
                "is_deliverable": False,
                "details": {"rate_limited": True}
            }
        
        # Set default sender address if not provided or is None
        if not sender_email:
            try:
                if hasattr(self.rate_limit_manager, 'get_smtp_limit'):
                    sender_email = self.rate_limit_manager.get_smtp_limit('default_sender_email')
                else:
                    sender_email = None
            except Exception:
                sender_email = "verification@example.com"  # Fallback only if database fails
        if sender_email is None:
            sender_email = "verification@example.com"
        
        # Track overall result - SIMPLIFIED validation criteria
        result = {
            "valid": False,
            "is_deliverable": False,
            "details": {
                "mx_servers_tried": 0,
                "ports_tried": 0,
                "connection_success": False,
                "smtp_banner": "",
                "smtp_conversation_success": False,  # This is what we really need
                "errors": [],
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
            
            # SIMPLIFIED SUCCESS CRITERIA: Either banner received OR conversation successful
            if details.get("connection_success") and (
                details.get("smtp_banner") or details.get("smtp_conversation_success")
            ):
                result["valid"] = True
                result["is_deliverable"] = True
                logger.info(f"[{trace_id}] Email {email} is valid via {mx_host}")
                break
        
        # Record the email checking result if at least one server was tried
        if mx_servers_tried > 0:
            if not result["valid"]:
                result["error"] = "All SMTP servers rejected the address or were unreachable"
            
            # Update for better context based on error codes
            if result["details"].get("smtp_error_code"):
                error_code = result["details"]["smtp_error_code"]
                if error_code == 550:
                    result["error"] = "Mailbox does not exist"
                elif error_code == 552:
                    result["error"] = "Mailbox full"
                elif error_code == 553:
                    result["error"] = "Mailbox name not allowed"
                elif 400 <= error_code < 500:
                    result["error"] = "Temporary server error"
        
        # Before returning the result, ensure critical fields are always present
        # This ensures the field names match what engine.py expects
        if "details" in result:
            # Ensure smtp_banner exists and has the right name
            result["details"]["smtp_banner"] = result["details"].get("smtp_banner", "")
            # Ensure port exists 
            if "port" not in result["details"]:
                result["details"]["port"] = None
            # Ensure server_message exists
            result["details"]["server_message"] = result["details"].get("server_message", "")
    
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
        
        # Use default timeouts from configuration
        connect_timeout = self.connect_timeout
        read_timeout = self.read_timeout
        
        # Track response time
        start_time = time.time()
        response_time_ms = 0
        
        sock = None
        try:
            # Create socket connection with default timeout
            with EnhancedOperationTimer("smtp_connect", {"host": mx_host, "port": port}) as timer:
                sock = socket.create_connection((mx_host, port), timeout=connect_timeout)
                
                # Wrap with SSL if needed
                if use_ssl:
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = context.wrap_socket(sock, server_hostname=mx_host)
                
                # Set default read timeout
                sock.settimeout(read_timeout)
                
                # Record success
                details["connection_success"] = True
                logger.debug(f"[{trace_id}] Connected to {mx_host}:{port} with timeouts (c:{connect_timeout:.1f}s, r:{read_timeout:.1f}s) using {'SSL/TLS' if use_ssl else 'plain'} connection")
        
            # Receive banner
            banner = self._receive_response(sock)
            details["smtp_banner"] = banner.replace('\n', ' ').replace('\r', '')
            logger.debug(f"[{trace_id}] Banner: {details['smtp_banner']}")
            
            # Send EHLO first (modern standard), fallback to HELO if needed
            ehlo_response = None
            try:
                logger.debug(f"[{trace_id}] Attempting EHLO with domain {domain}")
                self._send_command(sock, f"EHLO {domain}", trace_id)
                ehlo_response = self._receive_response(sock, trace_id)
                
                if not ehlo_response.startswith("250"):
                    # EHLO failed, try HELO
                    logger.debug(f"[{trace_id}] EHLO failed, trying HELO for {mx_host}")
                    self._send_command(sock, f"HELO {domain}", trace_id)
                    helo_response = self._receive_response(sock, trace_id)
                    
                    if not helo_response.startswith("250"):
                        details["errors"].append(f"Both EHLO and HELO failed: EHLO={ehlo_response}, HELO={helo_response}")
                        return False, details
                    else:
                        # HELO succeeded, but no extended capabilities
                        logger.debug(f"[{trace_id}] HELO succeeded for {mx_host}")
                        details["supports_starttls"] = False
                        details["supports_auth"] = False
                        details["vrfy_supported"] = False
                else:
                    # EHLO succeeded, check capabilities
                    logger.debug(f"[{trace_id}] EHLO succeeded for {mx_host}, analyzing capabilities")
                    details["supports_starttls"] = "STARTTLS" in ehlo_response
                    details["supports_auth"] = "AUTH" in ehlo_response
                    details["vrfy_supported"] = "VRFY" in ehlo_response
                    
            except Exception as e:
                error_msg = f"EHLO/HELO error: {str(e)}, type: {type(e).__name__}"
                logger.debug(f"[{trace_id}] {error_msg}")
                details["errors"].append(error_msg)
                return False, details
            
            # Try STARTTLS if supported and not already using SSL
            if details["supports_starttls"] and not use_ssl:
                self._send_command(sock, "STARTTLS")
                starttls_response = self._receive_response(sock)
                if starttls_response.startswith("220"):
                    # Upgrade to TLS
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = context.wrap_socket(sock, server_hostname=mx_host)
                    
                    # Need to send EHLO again after STARTTLS
                    self._send_command(sock, f"EHLO {domain}")
                    self._receive_response(sock)
            
            # Mail from
            from_cmd = f"MAIL FROM:<{sender_email}>"
            logger.debug(f"[{trace_id}] Sending MAIL FROM command")
            self._send_command(sock, from_cmd, trace_id)
            mail_from_response = self._receive_response(sock, trace_id)

            if not mail_from_response.startswith("250"):
                error_msg = f"MAIL FROM rejected: {mail_from_response}"
                logger.warning(f"[{trace_id}] {error_msg}")
                details["errors"].append(error_msg)
                details["smtp_flow_success"] = False
                details["failure_stage"] = "MAIL FROM"
                return False, details
            else:
                logger.debug(f"[{trace_id}] MAIL FROM accepted")

            # RCPT TO
            rcpt_cmd = f"RCPT TO:<{email}>"
            logger.debug(f"[{trace_id}] Sending RCPT TO command - this is the critical validation step")
            self._send_command(sock, rcpt_cmd, trace_id)

            # Record time when RCPT TO was sent for timeout analysis
            rcpt_to_sent_time = time.time()
            try:
                rcpt_response = self._receive_response(sock, trace_id)
                
                # Calculate response time for RCPT TO specifically
                rcpt_response_time = int((time.time() - rcpt_to_sent_time) * 1000)
                logger.debug(f"[{trace_id}] RCPT TO response received in {rcpt_response_time}ms")
                
                # Save the full message for analysis
                details["server_message"] = rcpt_response
                details["rcpt_to_response_time_ms"] = rcpt_response_time
                
            except socket.timeout as e:
                elapsed_time = int((time.time() - start_time) * 1000)
                error_msg = f"Timeout during SMTP connection to {mx_host}:{port} after {elapsed_time}ms: {str(e)}"
                logger.info(f"[{trace_id}] {error_msg}")
                details["errors"].append(error_msg)
                details["timeout_detected"] = True
                details["timeout_stage"] = traceback.extract_stack()[-2].name  # Get calling function name
                details["failure_stage"] = "RCPT TO response"
                return False, details
            
            # Extract SMTP code
            smtp_code_match = re.match(r"^(\d+)", rcpt_response)
            if smtp_code_match:
                details["smtp_error_code"] = int(smtp_code_match.group(1))
            
            # Mark as success if SMTP code starts with 250
            success = rcpt_response.startswith("250")
            details["smtp_flow_success"] = success
            
            # Calculate response time
            response_time_ms = int((time.time() - start_time) * 1000)
            
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
            
            # Log connection summary
            if success:
                logger.info(f"[{trace_id}] SMTP verification succeeded for {email} on {mx_host}:{port} in {response_time_ms}ms")
            else:
                # Determine failure reason
                failure_reason = "Unknown error"
                if "smtp_error_code" in details:
                    failure_reason = f"Error code {details['smtp_error_code']}"
                elif details.get("timeout_detected"):
                    failure_reason = "Timeout"
                elif details.get("errors"):
                    failure_reason = details["errors"][-1]  # Get the last error
                
                logger.info(f"[{trace_id}] SMTP verification failed for {email} on {mx_host}:{port}: {failure_reason}")

            return success, details
            
        except socket.timeout as e:
            elapsed_time = int((time.time() - start_time) * 1000)
            error_msg = f"Timeout during SMTP connection to {mx_host}:{port} after {elapsed_time}ms: {str(e)}"
            logger.info(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            details["timeout_detected"] = True
            details["timeout_stage"] = traceback.extract_stack()[-2].name  # Get calling function name
            
            # Update statistics specifically for timeout
            self._update_domain_stats(
                domain, 
                False, 
                int((time.time() - start_time) * 1000),
                error_type='timeout',
                trace_id=trace_id,
                mx_host=mx_host,  
                port=port         
            )

            # Add domain to temporary blocklist
            self._add_to_temporary_blocklist(domain, "SMTP timeout", trace_id)
            
            return False, details
        
        except socket.gaierror as e:
            error_code = e.args[0] if e.args else "unknown"
            error_msg = f"DNS resolution failed for {mx_host}:{port}: Error {error_code} - {str(e)}"
            logger.debug(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            return False, details
    
        except ssl.SSLError as e:
            error_msg = f"SSL error with {mx_host}:{port}: {str(e)}"
            logger.debug(f"[{trace_id}] {error_msg}")
            details["errors"].append(error_msg)
            return False, details

        except socket.error as e:
            error_code = e.args[0] if e.args else "unknown"
            error_msg = f"Socket error connecting to {mx_host}:{port}: Error {error_code} - {str(e)}"
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
    
    def _send_command(self, sock: socket.socket, command: str, trace_id: Optional[str] = None) -> None:
        """Send an SMTP command to the server"""
        # Mask sensitive data in logs
        log_command = command
        if command.startswith("MAIL FROM:") or command.startswith("RCPT TO:"):
            log_command = re.sub(r'<(.+?)>', '<***@***>', command)
            
        logger.debug(f"[{trace_id}] SMTP >> {log_command} ({datetime.now(timezone.utc).strftime('%H:%M:%S.%f')[:-3]})")
        sock.sendall(f"{command}\r\n".encode())

    def _receive_response(self, sock: socket.socket, trace_id: Optional[str] = None) -> str:
        """Receive and return SMTP server response"""
        start_time = time.time()
        response = []
        
        try:
            while True:
                line = sock.recv(1024).decode('utf-8', errors='ignore')
                if not line:
                    break
                    
                response.append(line)
                elapsed_ms = int((time.time() - start_time) * 1000)
                
                # If the 4th character is a space, we've reached the last line
                if len(line) > 3 and line[3] == ' ':
                    # Extract the SMTP code from the response
                    code = line[:3] if len(line) >= 3 and line[:3].isdigit() else "???"
                    logger.debug(f"[{trace_id}] SMTP << {code} response received in {elapsed_ms}ms " +
                               f"({datetime.now(timezone.utc).strftime('%H:%M:%S.%f')[:-3]})")
                    break
        except socket.timeout:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.debug(f"[{trace_id}] SMTP << TIMEOUT after {elapsed_ms}ms waiting for response")
            raise
        
        response_text = ''.join(response)
        # Log full response but truncate if too long
        if len(response_text) > 100:
            logger.debug(f"[{trace_id}] SMTP response: {response_text[:100]}...")
        else:
            logger.debug(f"[{trace_id}] SMTP response: {response_text}")
    
        return response_text
    
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
                    min_interval = self.rate_limit_manager.get_smtp_port25_conn_interval()
                elif port in (587, 465):
                    min_interval = self.rate_limit_manager.get_smtp_port587_conn_interval()
                else:
                    min_interval = self.rate_limit_manager.get_smtp_port25_conn_interval()  # Default
                
                if time_diff < min_interval:
                    logger.warning(f"[{trace_id}] Rate limit exceeded for {domain}. "
                                  f"Min interval: {min_interval}s, Time since last: {time_diff:.2f}s, "
                                  f"Need to wait: {min_interval - time_diff:.2f}s more")
                    return False
        
        # Use the rate limit manager's check_rate_limit method BEFORE updating last connection time
        try:
            # First record this attempt in the counter (important!)
            self.rate_limit_manager.record_usage('smtp', domain)
            
            # Then check if we've hit the limit
            is_exceeded, limit_info = self.rate_limit_manager.check_rate_limit(
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
        
        # Only update last connection time if we're actually allowing the connection
        _domain_last_connection[domain] = current_time
        return True
    
    def _is_domain_temporarily_blocked(self, domain: str, trace_id: Optional[str] = None) -> bool:
        """Check if domain is in temporary blocklist"""
        try:
            # Check cache first
            cache_key = CacheKeys.smtp_blocked(domain)
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Clean expired entries first
            current_time = datetime.now(timezone.utc)
            sync_db.execute(
                "DELETE FROM smtp_temporary_blocklist WHERE expires_at <= $1",
                current_time
            )
            
            # Check if domain is blocked
            blocked_entry = sync_db.fetchrow(
                "SELECT * FROM smtp_temporary_blocklist WHERE domain = $1 AND expires_at > $2",
                domain, current_time
            )
            
            is_blocked = blocked_entry is not None
            
            # Cache result for 60 seconds
            cache_manager.set(cache_key, is_blocked, ttl=60)
            
            if is_blocked:
                block_reason = blocked_entry['reason'] if blocked_entry else "Unknown reason"
                logger.debug(f"[{trace_id}] Domain {domain} is temporarily blocked: {block_reason}")
                    
            return is_blocked
            
        except Exception as e:
            logger.warning(f"[{trace_id}] Error checking temporary blocklist for {domain}: {e}")
            return False

    def _add_to_temporary_blocklist(self, domain: str, reason: str, trace_id: Optional[str] = None) -> None:
        """Add a domain to the temporary blocklist with TTL"""
        try:
            # Use configured values instead of hardcoded
            if "timeout" in reason.lower():
                block_seconds = self.rate_limit_manager.get_timeout_block_duration()
            elif "rate limit" in reason.lower():
                block_seconds = self.rate_limit_manager.get_rate_limit_block_duration()
            else:
                block_seconds = self.rate_limit_manager.get_smtp_limit('default_block_duration')
        
            current_time = datetime.now(timezone.utc)
            expires_at = current_time + timedelta(seconds=block_seconds)
            
            # Use UPSERT to handle existing entries
            sync_db.execute(
                """
                INSERT INTO smtp_temporary_blocklist (domain, reason, expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (domain) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    expires_at = EXCLUDED.expires_at,
                    block_count = smtp_temporary_blocklist.block_count + 1,
                    blocked_at = NOW()
                """,
                domain, reason, expires_at
            )
            
            # Invalidate cache
            cache_key = CacheKeys.smtp_blocked(domain)
            cache_manager.delete(cache_key)
            
            logger.info(f"[{trace_id}] Added {domain} to temporary blocklist for {block_seconds}s. Reason: {reason}")
            
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to add {domain} to temporary blocklist: {e}")

    def _check_retry_availability(self, domain: str) -> Tuple[bool, Optional[datetime]]:
        """Check if domain is available for retry based on backoff settings"""
        return self.stats_manager.check_retry_availability(domain)
    
    def _get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Get domain statistics and settings from database using UPSERT pattern"""
        return self.stats_manager.get_domain_stats(domain)
    
    def _update_domain_stats(self, domain: str, success: bool, 
                          response_time_ms: int = 0, error_code: Optional[int] = None,
                          error_type: Optional[str] = None, trace_id: Optional[str] = None,
                          mx_host: Optional[str] = None, port: Optional[int] = None):
        """Update domain statistics after an attempt"""
        self.stats_manager.update_domain_stats(
            domain, success, response_time_ms, error_code, error_type, trace_id, mx_host, port
        )
    
    def _update_geographic_info(self, domain: str, country_code=None, region=None, provider=None):
        """Update geographic information for a domain"""
        self.domain_info.update_geographic_info(domain, country_code, region, provider)

    def can_validate_domain(self, domain: str, trace_id: Optional[str] = None) -> Tuple[bool, str]:
        """Check if we can validate a domain without actually attempting connection"""
        # Check if domain is in backoff period
        retry_available, retry_time = self._check_retry_availability(domain)
        if not retry_available:
            wait_seconds = int((retry_time - datetime.now(timezone.utc)).total_seconds()) if retry_time else 0
            return False, f"Domain in backoff period. Wait {wait_seconds} seconds."
        
        # Check domain rate limits
        if not self._check_domain_rate_limit(domain, 25, trace_id):
            return False, "Rate limit exceeded for domain"
            
        return True, "OK"
    
    def validate_smtp_batch(self, emails: List[str], delay_between_domains: float = 1.0) -> List[Dict[str, Any]]:
        """Validate multiple emails with automatic delays to prevent rate limiting"""
        results = []
        last_domain = None
        
        for email in emails:
            if '@' not in email:
                results.append({'email': email, 'valid': False, 'error': 'Invalid format'})
                continue
                
            domain = email.split('@')[1]
            
            # Add delay between different domains
            if last_domain and last_domain != domain:
                time.sleep(delay_between_domains)
                
            # Check if we can validate this domain
            can_validate, reason = self.can_validate_domain(domain)
            if not can_validate:
                results.append({
                    'email': email, 
                    'valid': False, 
                    'error': f"Skipped: {reason}",
                    'is_deliverable': False
                })
                continue
                
            # Validate the email
            result = self.verify_email(email, domain, [], None, None)
            results.append(result)
            
            last_domain = domain
            
        return results

    def get_max_connections_per_domain(self) -> int:
        """Get max connections per domain from rate limit manager"""
        try:
            return self.rate_limit_manager.get_smtp_limit('max_connections_per_domain')
        except Exception as e:
            logger.warning(f"Failed to get max_connections_per_domain: {e}, using default")
            return 5  # Default fallback

    def get_smtp_port25_conn_interval(self) -> float:
        """Get minimum interval between SMTP connections"""
        try:
            return float(self.rate_limit_manager.get_auth_security_limit('smtp_port25_conn_interval'))
        except Exception:
            return 10.0  # Default 10 seconds

    def get_cache_limit(self, key: str) -> int:
        """Get cache TTL from rate limit manager"""
        try:
            return self.rate_limit_manager.get_cache_limit(key)
        except Exception:
            return 3600  # Default 1 hour
        
# Add global connection counter with decay in rate_limit_manager
def check_global_rate_limit(self, category: str) -> bool:
    current_minute = int(time.time() / 60)
    counter_key = f"global_rate:{category}:{current_minute}"
    
    # Get current count and increment
    current = cache_manager.get(counter_key) or 0
    cache_manager.set(counter_key, current + 1, ttl=120)  # 2 min TTL
    
    max_allowed = self.get_smtp_limit('max_connections_per_minute')
    return current < max_allowed

from src.helpers.tracer import (
    ensure_trace_id, 
    ensure_context_has_trace_id, 
    trace_function, 
    validate_trace_id
)

@trace_function("validate_smtp")
def validate_smtp(context):
    """Validate email via SMTP connection"""
    
    # Ensure context has valid trace_id
    context = ensure_context_has_trace_id(context)
    trace_id = context['trace_id']
    
    # Validate trace_id at entry point
    if not validate_trace_id(trace_id):
        logger.error(f"Invalid trace_id received in validate_smtp: {trace_id}")
        trace_id = ensure_trace_id()
        context['trace_id'] = trace_id

    # Extract email from context
    email = context.get('email')
    logger.debug(f"[{trace_id}] Starting SMTP validation for {email}")
    
    # Parse and validate email format
    parsing_result = _parse_and_validate_email(email if email is not None else "")
    if not parsing_result["valid"]:
        return parsing_result
    
    local_part, domain = parsing_result["parts"]
    
    # Check cache first
    cache_key = CacheKeys.smtp_result(email)
    cached_result = cache_manager.get(cache_key)
    if cached_result:
        logger.debug(f"[{trace_id}] Using cached SMTP validation result for {email}")
        return cached_result
    
    # Check blacklist/whitelist status first
    try:
        from src.engine.functions.bw import check_black_white
        bw_result = check_black_white(context)
        # Store the result in context for later use
        context['bw_result'] = bw_result
        
        # If domain is blacklisted, skip SMTP validation
        if bw_result.get('blacklisted', False):
            logger.info(f"[{trace_id}] Domain {domain} is blacklisted by {bw_result.get('source', 'unknown')}. Skipping SMTP validation.")
            return {
                'valid': False,
                'error': f"Domain is blacklisted: {bw_result.get('source', 'Unknown blacklist')}",
                'is_deliverable': False,
                'blacklisted': True,
                'smtp_result': False,
                'email': email,
                'blacklist_info': {
                    'blacklisted': True,
                    'source': bw_result.get('source', 'Unknown'),
                    'whitelisted': False
                }
            }
            
        # If domain is whitelisted, log it but continue with validation
        if bw_result.get('whitelisted', False):
            logger.info(f"[{trace_id}] Domain {domain} is whitelisted by {bw_result.get('source', 'unknown')}. Proceeding with SMTP validation.")
    except Exception as e:
        logger.warning(f"[{trace_id}] Failed to check black/white list: {str(e)}")
    
    # Get or fetch MX records
    mx_result = _get_mx_records(context, domain, trace_id)
    if not mx_result["valid"]:
        return mx_result["result"]
    
    mx_records = mx_result["records"]
    
    # Get sender email from configuration
    sender_email = _get_sender_email(trace_id)
    
    # Initialize SMTP validator and extract geographic info
    test_mode = context.get('test_mode', False)
    validator = SMTPValidator(test_mode=test_mode)
    
    # Perform validation with timing
    with EnhancedOperationTimer("smtp_validation", {"email": email}) as timer:
        safe_email = email if email is not None else ""
        result = validator.verify_email(safe_email, domain, mx_records, sender_email, trace_id, context=context)
    
    # Add execution time
    result['execution_time'] = timer.elapsed_ms
    
    # Normalize and standardize the result structure
    result = _normalize_validation_result(result, email, trace_id)
    
    # Cache the result
    cache_manager.set(cache_key, result, ttl=validator.cache_ttl)
    
    return result

def _parse_and_validate_email(email: str) -> Dict[str, Any]:
    """Parse and perform basic validation on email format"""
    if not email or '@' not in email:
        return {
            'valid': False,
            'error': 'Invalid email format',
            'is_deliverable': False,
            'details': {
                'error_message': 'Invalid email format',
                'connection_success': False,
                'smtp_flow_success': False
            }
        }
    
    try:
        local_part, domain = email.rsplit('@', 1)
        return {
            "valid": True,
            "parts": (local_part, domain)
        }
    except ValueError:
        return {
            'valid': False,
            'error': 'Invalid email format',
            'is_deliverable': False,
            'details': {
                'error_message': 'Invalid email format',
                'connection_success': False,
                'smtp_flow_success': False
            }
        }

def _get_mx_records(context: Dict[str, Any], domain: str, trace_id: str) -> Dict[str, Any]:
    """Extract MX records from context or fetch them if not present"""
    # Get MX records if already in context
    mx_records = context.get('mx_records')
    if not mx_records:
        mx_result = context.get('mx_records_result')
        if mx_result and isinstance(mx_result, dict):
            mx_records = mx_result.get('records')
    
    # If still no MX records, fetch them
    if not mx_records:
        logger.debug(f"[{trace_id}] No MX records in context for {domain}, fetching...")
        
        try:
            from src.engine.functions.mx import fetch_mx_records
            mx_result = fetch_mx_records(context)
            mx_records = mx_result.get('records', [])
            # Store the complete result in context
            context['mx_records_result'] = mx_result
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to fetch MX records for {domain}: {e}")
            return {
                "valid": False,
                "result": {
                    'valid': False,
                    'error': f"Failed to retrieve MX records: {str(e)}",
                    'is_deliverable': False,
                    'details': {
                        'error_message': f"Failed to retrieve MX records: {str(e)}",
                        'connection_success': False,
                        'smtp_flow_success': False
                    }
                }
            }
    
    # No MX records found
    if not mx_records:
        logger.info(f"[{trace_id}] No MX records found for {domain}")
        return {
            "valid": False,
            "result": {
                'valid': False,
                'error': 'No MX records found for domain',
                'is_deliverable': False,
                'details': {
                    'error_message': 'No MX records found for domain',
                    'smtp_banner': "",
                    'port': None,
                    'server_message': "",
                    'connection_success': False,
                    'smtp_flow_success': False,
                    'errors': [],
                    'ports_tried': 0,
                    'mx_servers_tried': 0
                }
            }
        }
    
    return {
        "valid": True,
        "records": mx_records
    }

def _get_sender_email(trace_id: str) -> str:
    """Get sender email from configuration with fallback"""
    try:
        # Attempt to get from configuration
        result = sync_db.fetchrow("""
            SELECT value FROM app_settings
            WHERE category = 'email' AND sub_category = 'defaults' AND name = 'sender email'
        """)
        
        if result and result['value']:
            sender_email = result['value']
            logger.debug(f"[{trace_id}] Using sender email: {sender_email}")
            return sender_email
    except Exception as e:
        logger.warning(f"[{trace_id}] Failed to get sender email from config: {e}")
    
    # Fallback
    default_sender = "verification@example.com"
    logger.debug(f"[{trace_id}] Using default sender email: {default_sender}")
    return default_sender



def _normalize_validation_result(validation_data, email, trace_id):
    """Normalize SMTP validation result"""
    
    # Ensure we have a valid trace_id
    trace_id = ensure_trace_id(trace_id)
    
    # Create a new normalized result with standard attribute names
    normalized_result = {
        "valid": validation_data.get("valid", False),
        "is_deliverable": validation_data.get("is_deliverable", False),
        "email": email,
    }
    
    # Extract values from either top level or nested details
    details = validation_data.get("details", {})
    
    # Copy error information
    if "error" in validation_data:
        normalized_result["error_message"] = validation_data["error"]
    elif "errors" in validation_data and validation_data["errors"]:
        normalized_result["error_message"] = validation_data["errors"][0]
    elif "error_message" in details:
        normalized_result["error_message"] = details["error_message"]
    elif "errors" in details and details["errors"]:
        normalized_result["error_message"] = details["errors"][0]
    
    # Map all SMTP fields directly to top level with standardized names
    normalized_result["smtp_result"] = validation_data.get("valid", False)
    normalized_result["smtp_banner"] = details.get("smtp_banner", "") or details.get("banner", "")
    
    # Add explicit debug logging to track banner values
    logger.debug(f"[{trace_id}] SMTP_BANNER_DEBUG: Raw banner from details={{smtp_banner: '{details.get('smtp_banner', '')}', banner: '{details.get('banner', '')}'}} → Final: '{normalized_result['smtp_banner']}'")
    
    normalized_result["smtp_vrfy"] = details.get("vrfy_supported", False)
    normalized_result["smtp_supports_tls"] = details.get("supports_starttls", False)
    normalized_result["smtp_supports_auth"] = details.get("supports_auth", False)
    normalized_result["smtp_flow_success"] = details.get("smtp_flow_success", False) or details.get("smtp_conversation_success", False)
    normalized_result["smtp_error_code"] = details.get("smtp_error_code")
    normalized_result["smtp_server_message"] = details.get("server_message", "")
    
    # Add additional fields that might be useful elsewhere
    normalized_result["port"] = details.get("port")
    normalized_result["connection_success"] = details.get("connection_success", False)
    normalized_result["ports_tried"] = details.get("ports_tried", 0)
    normalized_result["mx_servers_tried"] = details.get("mx_servers_tried", 0)
    
    # Copy execution time if available
    if "execution_time" in validation_data:
        normalized_result["execution_time"] = validation_data["execution_time"]
    
    # Log result summary
    logger.info(f"[{trace_id}] SMTP validation for {email}: {'SUCCESS' if normalized_result['smtp_result'] else 'FAILURE'}")
    
    # NO MORE nested details dictionary - everything is at the top level!
    return normalized_result