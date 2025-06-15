"""
Email Verification Engine
===================================
IPv4 DNS Resolver:
This module provides IPv4-specific DNS resolution functionality.
"""

import dns.resolver
from typing import List, Optional, Any
from src.managers.log import get_logger

# Set up logging
logger = get_logger()

class IPv4Resolver:
    """
    IPv4 DNS resolver functionality
    """
    
    def resolve(self, hostname: str, record_type: str, 
                nameservers: Optional[List[str]] = None,
                timeout: float = 5.0,
                use_tcp: bool = False,
                use_edns: bool = False,
                edns_payload: int = 1232) -> dns.resolver.Answer:
        """
        Resolve DNS records using IPv4
        
        Args:
            hostname: The hostname to query
            record_type: The type of DNS record (A, MX, TXT, etc.)
            nameservers: List of nameserver IP addresses to use (required)
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            use_edns: Whether to use EDNS extensions
            edns_payload: EDNS payload size
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            ValueError: If no valid IPv4 nameservers are provided
            Various DNS exceptions if resolution fails
        """
        resolver = dns.resolver.Resolver()
        
        # Require nameservers and validate they are IPv4 (no colons)
        if not nameservers:
            raise ValueError("IPv4 nameservers must be provided, no fallbacks available")
        
        ipv4_ns = [ns for ns in nameservers if ':' not in ns]
        if not ipv4_ns:
            raise ValueError("No valid IPv4 nameservers provided (IPv4 addresses must not contain colons)")
        
        # Set the nameservers
        resolver.nameservers = ipv4_ns
        
        # Set timeout
        resolver.timeout = timeout
        resolver.lifetime = timeout * 1.5  # slightly longer for total operation
        
        # Configure EDNS if requested
        if use_edns:
            try:
                resolver.use_edns(0, payload=edns_payload)
            except Exception as e:
                logger.warning(f"Failed to configure EDNS: {e}")
        
        # Perform the resolution
        return resolver.resolve(hostname, record_type, tcp=use_tcp)
    
    def check_ipv4_connectivity(self, nameservers: List[str]) -> bool:
        """
        Test if IPv4 connectivity is working with provided nameservers
        
        Args:
            nameservers: List of IPv4 nameserver addresses to test
            
        Returns:
            Boolean indicating if IPv4 is working
            
        Raises:
            ValueError: If no valid IPv4 nameservers are provided
        """
        if not nameservers:
            raise ValueError("IPv4 nameservers must be provided for connectivity check")
        
        ipv4_ns = [ns for ns in nameservers if ':' not in ns]
        if not ipv4_ns:
            raise ValueError("No valid IPv4 nameservers provided for connectivity check")
        
        for server in ipv4_ns:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = 2.0
                
                # Try to resolve a common domain
                resolver.resolve("google.com", "A")
                return True
                
            except Exception:
                # Try the next server
                continue
        
        # If we get here, all tests failed
        return False
    
    def resolve_with_multiple_servers(self, hostname: str, record_type: str, 
                                    nameservers: List[str],
                                    timeout: float = 5.0,
                                    use_tcp: bool = False) -> dns.resolver.Answer:
        """
        Try multiple nameservers in sequence without fallback to defaults
        
        Args:
            hostname: The hostname to query
            record_type: The type of DNS record (A, MX, TXT, etc.)
            nameservers: List of nameserver IP addresses to use (required)
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            ValueError: If no valid IPv4 nameservers are provided
            dns.resolver.NXDOMAIN: If the domain does not exist
            dns.resolver.NoAnswer: If the domain exists but has no records of the requested type
            dns.exception.Timeout: If all nameservers timed out
        """
        if not nameservers:
            raise ValueError("IPv4 nameservers must be provided, no fallbacks available")
        
        # Filter to IPv4 only
        ns_to_try = [ns for ns in nameservers if ':' not in ns]
        
        if not ns_to_try:
            raise ValueError("No valid IPv4 nameservers provided")
        
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
                logger.debug(f"Nameserver {ns} failed: {e}")
                last_error = e
        
        # If we get here, all nameservers failed
        if last_error:
            raise last_error
        else:
            raise dns.resolver.Timeout("All nameservers timed out or failed")