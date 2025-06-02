"""
Email Verification Engine
===================================
IPv4 DNS Resolver:
This module provides IPv4-specific DNS resolution functionality.
"""

import dns.resolver
from typing import List, Optional, Any
from src.managers.log import Axe

# Set up logging
logger = Axe()

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
            nameservers: List of nameserver IP addresses to use
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            use_edns: Whether to use EDNS extensions
            edns_payload: EDNS payload size
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            Various DNS exceptions if resolution fails
        """
        resolver = dns.resolver.Resolver()
        
        # Configure resolver with nameservers if provided
        if nameservers:
            # Filter to only IPv4 addresses
            ipv4_ns = [ns for ns in nameservers if ':' not in ns]
            if ipv4_ns:
                resolver.nameservers = ipv4_ns
            else:
                # If no IPv4 nameservers provided, use defaults
                logger.warning("No IPv4 nameservers provided, using defaults")
                resolver.nameservers = self.get_default_nameservers()
        else:
            resolver.nameservers = self.get_default_nameservers()
        
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
    
    def get_default_nameservers(self) -> List[str]:
        """
        Get a list of reliable IPv4 DNS servers
        
        Returns:
            List of IPv4 nameserver addresses
        """
        return [
            # Cloudflare
            "1.1.1.1",
            "1.0.0.1",
            
            # Google DNS
            "8.8.8.8",
            "8.8.4.4",
            
            # Quad9
            "9.9.9.9",
            "149.112.112.112",
            
            # OpenDNS
            "208.67.222.222",
            "208.67.220.220"
        ]
    
    def check_ipv4_connectivity(self) -> bool:
        """
        Test if IPv4 connectivity is working
        
        Returns:
            Boolean indicating if IPv4 is working
        """
        test_servers = [
            "1.1.1.1",  # Cloudflare
            "8.8.8.8"   # Google
        ]
        
        for server in test_servers:
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
    
    def resolve_with_fallback(self, hostname: str, record_type: str, 
                             nameservers: Optional[List[str]] = None,
                             timeout: float = 5.0,
                             use_tcp: bool = False) -> dns.resolver.Answer:
        """
        Resolve DNS with automatic fallback between nameservers
        
        Args:
            hostname: The hostname to query
            record_type: The type of DNS record (A, MX, TXT, etc.)
            nameservers: List of nameserver IP addresses to use
            timeout: Timeout in seconds
            use_tcp: Whether to use TCP instead of UDP
            
        Returns:
            dns.resolver.Answer object
            
        Raises:
            dns.resolver.NXDOMAIN: If the domain does not exist
            dns.resolver.NoAnswer: If the domain exists but has no records of the requested type
            dns.exception.Timeout: If all nameservers timed out
        """
        # Get nameservers to try
        ns_to_try = nameservers if nameservers else self.get_default_nameservers()
        ns_to_try = [ns for ns in ns_to_try if ':' not in ns]  # Filter to IPv4 only
        
        if not ns_to_try:
            ns_to_try = self.get_default_nameservers()
        
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