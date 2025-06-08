"""
Email Verification Engine
===================================
IPv6 DNS Resolver:
This module provides IPv6-specific DNS resolution functionality.
"""

import dns.resolver
import socket
import subprocess
import os
from typing import List, Optional, Any, Dict
from src.managers.log import Axe

# Set up logging
logger = Axe()

class IPv6Resolver:
    """
    IPv6 DNS resolver functionality
    """
    
    # Cache the availability result to avoid repeated checks
    _ipv6_available = None
    
    def resolve(self, hostname: str, record_type: str, 
                nameservers: Optional[List[str]] = None,
                timeout: float = 5.0,
                use_tcp: bool = False,
                use_edns: bool = False,
                edns_payload: int = 1232) -> dns.resolver.Answer:
        """
        Resolve DNS records using IPv6
        
        Args:
            hostname: The hostname to query
            record_type: The type of DNS record (A, MX, TXT, etc.)
            nameservers: List of IPv6 nameserver addresses (REQUIRED) - must contain colons
                        (no fallback to defaults)
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            use_edns: Whether to use EDNS extensions
            edns_payload: EDNS payload size
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            ValueError: If IPv6 is not available or no valid nameservers provided
            Various DNS exceptions if resolution fails
        """
        # Check IPv6 availability first
        if not self.is_available():
            raise ValueError("IPv6 DNS resolution requested but IPv6 is not available on this system")
        
        resolver = dns.resolver.Resolver()
        
        # Require nameservers and validate they are IPv6 (contain colons)
        if not nameservers:
            raise ValueError("IPv6 nameservers must be provided, no fallbacks available")
        
        ipv6_ns = [ns for ns in nameservers if ':' in ns]
        if not ipv6_ns:
            raise ValueError("No valid IPv6 nameservers provided (IPv6 addresses must contain colons)")
        
        # Set the nameservers
        resolver.nameservers = ipv6_ns
        
        # Set timeout
        resolver.timeout = timeout
        resolver.lifetime = timeout * 1.5  # slightly longer for total operation
        
        # Configure EDNS if requested
        if use_edns:
            try:
                resolver.use_edns(0, payload=edns_payload)
            except Exception as e:
                logger.warning(f"Failed to configure EDNS for IPv6: {e}")
        
        # Perform the resolution
        return resolver.resolve(hostname, record_type, tcp=use_tcp)
       
    def is_available(self, test_servers: Optional[List[str]] = None) -> bool:
        """
        Check if IPv6 is available on this system
        
        This method only tests system IPv6 connectivity with common DNS servers
        for internal functionality checking. It is NOT used for actual DNS resolution.
        
        Args:
            test_servers: Optional list of IPv6 servers to test connectivity with
                          (only used for availability testing, not DNS resolution)
        
        Returns:
            Boolean indicating if IPv6 is working
        """
        # Use cached result if available
        if IPv6Resolver._ipv6_available is not None:
            return IPv6Resolver._ipv6_available
        
        # Start with basic socket test
        try:
            # Try to create an IPv6 socket
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.close()
        except Exception as e:
            logger.debug(f"IPv6 socket creation failed: {e}")
            IPv6Resolver._ipv6_available = False
            return False
            
        # If socket creation works, check for actual IPv6 interfaces
        try:
            if os.name == 'nt':  # Windows
                output = subprocess.check_output("ipconfig", universal_newlines=True)
                if "IPv6 Address" not in output:
                    logger.debug("No IPv6 interfaces found in Windows ipconfig")
                    IPv6Resolver._ipv6_available = False
                    return False
            else:  # Linux/Unix/macOS
                output = subprocess.check_output(["ip", "-6", "addr"], universal_newlines=True)
                if "inet6" not in output or self._only_loopback_in_output(output):
                    logger.debug("No non-loopback IPv6 interfaces found on Unix-like system")
                    IPv6Resolver._ipv6_available = False
                    return False
        except Exception as e:
            logger.debug(f"Error checking IPv6 interfaces: {e}")
            # Continue to next test even if this fails
        
        # Finally, test actual connectivity to an IPv6 DNS server
        # These servers are used ONLY for testing connectivity, not for actual DNS resolution
        if test_servers is None:
            test_servers = [
                "2606:4700:4700::1111",  # Cloudflare
                "2001:4860:4860::8888"   # Google
            ]
        
        for server in test_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = 2.0
                
                # Try to resolve a common domain
                resolver.resolve("google.com", "A")
                
                # If we get here, IPv6 DNS resolution works
                logger.info(f"IPv6 DNS resolution is working with {server}")
                IPv6Resolver._ipv6_available = True
                return True
                
            except Exception as e:
                logger.debug(f"IPv6 test with {server} failed: {e}")
                # Try the next server
        
        # If we get here, all tests failed
        logger.info("IPv6 is not available or not working properly")
        IPv6Resolver._ipv6_available = False
        return False
    
    def _only_loopback_in_output(self, output: str) -> bool:
        """
        Check if only loopback IPv6 interfaces are present in network interface output
        
        Args:
            output: String output from network interface command
            
        Returns:
            True if only loopback interfaces are found
        """
        has_loopback = "::1" in output
        has_global = any(addr in output for addr in [
            "2001:", "2002:", "2003:", "2600:", "2601:", "2602:", "2603:", 
            "2604:", "2605:", "2606:", "2607:", "2a00:", "2a01:", "2a02:",
            "2a03:", "2a04:", "2a05:", "2a06:", "2a07:", "2a08:", "2a09:",
            "2a10:", "fd"
        ])
        return has_loopback and not has_global
    
    def resolve_with_multiple_servers(self, hostname: str, record_type: str, 
                         nameservers: List[str],
                         timeout: float = 5.0,
                         use_tcp: bool = False) -> dns.resolver.Answer:
        """
        Try multiple nameservers in sequence without fallback to defaults
        
        Args:
            hostname: The hostname to query
            record_type: The type of DNS record (A, MX, TXT, etc.)
            nameservers: List of IPv6 nameserver addresses (REQUIRED) - must contain colons
                        (no fallback to defaults)
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            ValueError: If IPv6 is not available or no valid nameservers provided
            dns.resolver.NXDOMAIN: If the domain does not exist
            dns.resolver.NoAnswer: If the domain exists but has no records of the requested type
            dns.exception.Timeout: If all nameservers timed out
        """
        # Check IPv6 availability first
        if not self.is_available():
            raise ValueError("IPv6 DNS resolution requested but IPv6 is not available on this system")
        
        # Validate nameservers
        if not nameservers:
            raise ValueError("IPv6 nameservers must be provided, no fallbacks available")
    
        # Filter to IPv6 only
        ns_to_try = [ns for ns in nameservers if ':' in ns]
        
        if not ns_to_try:
            raise ValueError("No valid IPv6 nameservers provided (IPv6 addresses must contain colons)")
        
        # Try each nameserver
        last_error = None
        for ns in ns_to_try:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ns]
                resolver.timeout = timeout
                
                return resolver.resolve(hostname, record_type, tcp=use_tcp)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                # These are definitive answers - don't try other nameservers
                raise
                
            except Exception as e:
                # Log but continue to next nameserver
                logger.debug(f"IPv6 nameserver {ns} failed: {e}")
                last_error = e
    
        # If we get here, all nameservers failed
        if last_error:
            raise last_error
        else:
            raise dns.resolver.Timeout("All IPv6 nameservers timed out or failed")