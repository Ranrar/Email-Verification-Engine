"""
Email Verification Engine - MX Record Cache Script
=====================
Efficiently caches MX records for domains using the 3-level cache system.
Uses DNS rotation, respects rate limits, and provides detailed logging.

Single domain:
python scripts/mx_cache.py -d example.com

Process multiple domains from a file:
python scripts/mx_cache.py -f domains.txt
"""

import dns.resolver
import dns.reversename
import time
import sys
import argparse
import socket
import ipaddress
import re
import whois
import subprocess
from datetime import datetime
from dateutil.parser import parse 
from typing import List, Dict, Any

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager
from src.managers.time import TimeManager, now_utc, EnhancedOperationTimer
from src.managers.log import Axe

# Initialize logging
logger = Axe()

class MXCacher:
    """Simple utility to cache MX records efficiently."""
    
    def __init__(self):
        """Initialize with required managers and settings."""
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        self.time_manager = TimeManager()
        
        # Load optimal settings
        self.dns_timeout = self.dns_manager.get_setting('timeout')
        self.max_attempts = int(self.dns_manager.get_setting('max_attempts'))
        self.selection_strategy = self.dns_manager.get_setting('selection_strategy')
        
        # Get TTL settings from rate limit manager
        self.mx_ttl = self.rate_limit_manager.get_mx_records_cache_ttl()
        
        # Log initialization
        logger.info(f"MX Cacher initialized - DNS Strategy: {self.selection_strategy}, "
                   f"Timeout: {self.dns_timeout}s, TTL: {self.mx_ttl}s")
    
    def fetch_and_cache_mx(self, domain: str) -> Dict[str, Any]:
        """
        Fetch and cache MX records for a domain.
        
        Args:
            domain: Domain to fetch MX records for
            
        Returns:
            Dict containing MX records and status information
        """
        # Create standardized cache key
        cache_key = CacheKeys.mx_records(domain)
        
        # Check if already in cache
        cached_mx = cache_manager.get(cache_key)
        if cached_mx:
            logger.info(f"Cache hit for {domain} MX records")
            return {
                "domain": domain,
                "mx_records": cached_mx,
                "source": "cache",
                "timestamp": now_utc()
            }
        
        # Check rate limits before proceeding
        if not self.rate_limit_manager.check_rate_limit('dns', domain, 'mx_lookup'):
            logger.warning(f"Rate limit exceeded for {domain} MX lookup")
            return {
                "domain": domain,
                "mx_records": None,
                "error": "Rate limit exceeded",
                "timestamp": now_utc()
            }
        
        # Use enhanced timer to measure operation duration
        with EnhancedOperationTimer("mx_lookup", metadata={"domain": domain}) as timer:
            try:
                # Use DNS manager to fetch with rotation
                mx_records = []
                answers = dns.resolver.resolve(domain, 'MX')
                
                for rdata in answers:
                    parts = rdata.to_text().split()
                    if len(parts) >= 2:
                        preference = int(parts[0])
                        exchange = parts[1].rstrip('.')
                        mx_records.append({
                            'preference': preference, 
                            'exchange': exchange
                        })
                
                mx_records.sort(key=lambda x: x['preference'])
                
                # Record success in timer
                timer.add_metadata("record_count", len(mx_records))
                timer.add_metadata("success", True)
                
                # Cache the result
                cache_manager.set(cache_key, mx_records, ttl=self.mx_ttl)
                logger.info(f"Cached MX records for {domain}: {len(mx_records)} records with TTL {self.mx_ttl}s")
                
                # Record rate limit usage
                self.rate_limit_manager.record_usage('dns', domain)
                
                return {
                    "domain": domain,
                    "mx_records": mx_records,
                    "source": "dns_query",
                    "timestamp": now_utc(),
                    "duration_ms": timer.elapsed_ms
                }
                
            except dns.resolver.NXDOMAIN:
                timer.add_metadata("error", "NXDOMAIN")
                logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
                # Cache negative result with shorter TTL
                cache_manager.set(cache_key, [], ttl=300)
                return {
                    "domain": domain,
                    "mx_records": [],
                    "error": "Domain does not exist",
                    "timestamp": now_utc(),
                    "duration_ms": timer.elapsed_ms
                }
                
            except dns.resolver.NoAnswer:
                timer.add_metadata("error", "NoAnswer")
                logger.warning(f"No MX records for {domain}")
                # Cache negative result with shorter TTL
                cache_manager.set(cache_key, [], ttl=300)
                return {
                    "domain": domain,
                    "mx_records": [],
                    "error": "No MX records",
                    "timestamp": now_utc(),
                    "duration_ms": timer.elapsed_ms
                }
                
            except Exception as e:
                timer.add_metadata("error", str(e))
                logger.error(f"Error fetching MX for {domain}: {e}")
                return {
                    "domain": domain,
                    "mx_records": None,
                    "error": str(e),
                    "timestamp": now_utc(),
                    "duration_ms": timer.elapsed_ms
                }

def process_domains_file(filename: str) -> None:
    """Process a file containing domains, one per line."""
    mx_cacher = MXCacher()
    
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Processing {len(domains)} domains from {filename}")
        
        results = {
            "total": len(domains),
            "success": 0,
            "errors": 0,
            "cached": 0,
            "providers": {}  # Track providers encountered
        }
        
        for i, domain in enumerate(domains):
            logger.info(f"Processing {i+1}/{len(domains)}: {domain}")
            result = mx_cacher.fetch_and_cache_mx(domain)
            
            if result.get("error"):
                results["errors"] += 1
            else:
                results["success"] += 1
                if result.get("source") == "cache":
                    results["cached"] += 1
                
                # Track provider information if available
                if "email_provider" in result and result["email_provider"].get("provider_name"):
                    provider = result["email_provider"].get("provider_name")
                    if provider not in results["providers"]:
                        results["providers"][provider] = 0
                    results["providers"][provider] += 1
            
            # Be nice to DNS servers - add small delay between requests
            time.sleep(0.1)
        
        logger.info(f"Completed processing: {results}")
        
    except Exception as e:
        logger.error(f"Error processing file {filename}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MX Record Cacher')
    parser.add_argument('--file', '-f', help='File containing domains, one per line')
    parser.add_argument('--domain', '-d', help='Single domain to check')
    
    args = parser.parse_args()
    
    if args.file:
        process_domains_file(args.file)
    elif args.domain:
        mx_cacher = MXCacher()
        result = mx_cacher.fetch_and_cache_mx(args.domain)
        print(f"MX Records for {args.domain}:")
        if result.get("error"):
            print(f"Error: {result['error']}")
        else:
            for mx in result["mx_records"]:
                print(f"  Preference: {mx['preference']}, Exchange: {mx['exchange']}")
    else:
        parser.print_help()
        sys.exit(1)

def fetch_mx_records(context):
    """
    Fetch MX records for an email's domain with comprehensive infrastructure analysis.
    
    Args:
        context: Dictionary containing email address and trace_id
        
    Returns:
        Dict with MX validation results including infrastructure details
    """
    email = context.get("email", "")
    trace_id = context.get("trace_id", "")
    
    if not email or '@' not in email:
        return {
            "valid": False, 
            "error": "Invalid email format, cannot extract domain",
            "records": None,
            "has_mx": False,
            "execution_time": 0
        }
    
    # Extract domain from email
    domain = email.split('@')[1].strip().lower()
    
    # Use existing MXCacher to lookup records
    mx_cacher = MXCacher()
    mx_result = mx_cacher.fetch_and_cache_mx(domain)
    
    # Format result for validation system
    mx_records = mx_result.get("mx_records", [])
    is_fallback = False
    
    # If no MX records found, try A/AAAA records as fallback (RFC 5321 compliant)
    a_records = []  # Ensure a_records is always defined
    if not mx_records and not (mx_result.get("error") == "Domain does not exist"):
        logger.info(f"[{trace_id}] No MX records for {domain}, attempting A record fallback")
        
        try:
            # Check cache first
            cache_key = CacheKeys.a_records(domain)
            cached_records = cache_manager.get(cache_key)
            
            if cached_records:
                logger.debug(f"[{trace_id}] Cache hit for {domain} A records")
                a_records = cached_records
            else:
                # Lookup A records
                with EnhancedOperationTimer("a_record_lookup", metadata={"domain": domain}) as timer:
                    answers = dns.resolver.resolve(domain, 'A')
                    a_records = [str(rdata) for rdata in answers]
                    
                    # Cache the results
                    if a_records:
                        cache_manager.set(cache_key, a_records, ttl=1800)  # 30 min TTL
            
            # If A records found, create synthetic MX records using domain as exchange
            if a_records:
                mx_records = [{'preference': 0, 'exchange': domain, 'is_fallback': True}]
                is_fallback = True
                logger.info(f"[{trace_id}] Using A record fallback for {domain}: {a_records}")
                
        except Exception as e:
            logger.warning(f"[{trace_id}] A record fallback lookup failed for {domain}: {str(e)}")
    
    # Extract preferences and exchanges for easier access
    preferences = []
    exchanges = []
    if mx_records:
        preferences = [mx['preference'] for mx in mx_records]
        exchanges = [mx['exchange'] for mx in mx_records]
    
    # Group MX records by preference for load balancing analysis
    mx_groups = {}
    primary_mx = None
    backup_mx = []
    
    for mx in mx_records:
        pref = mx['preference']
        if pref not in mx_groups:
            mx_groups[pref] = []
        mx_groups[pref].append(mx['exchange'])
        
    # Identify primary and backup servers
    if mx_groups:
        sorted_prefs = sorted(mx_groups.keys())
        primary_pref = sorted_prefs[0]
        primary_mx = {
            "preference": primary_pref,
            "servers": mx_groups[primary_pref]
        }
        
        # All other preference groups are backups
        for pref in sorted_prefs[1:]:
            backup_mx.append({
                "preference": pref,
                "servers": mx_groups[pref]
            })
    
    # Resolve IP addresses (IPv4 and IPv6) for MX records
    ip_data = {
        "ipv4": [],
        "ipv6": [],
        "geo": {}
    }
    mx_ip_mapping = []

    if exchanges:
        dns_manager = DNSManager()
        rate_limit_manager = RateLimitManager()
        
        for mx_host in exchanges:
            # Check rate limits
            if not rate_limit_manager.check_rate_limit('dns', mx_host, 'ip_lookup'):
                logger.warning(f"[{trace_id}] Rate limit exceeded for {mx_host} IP lookup")
                continue
                
            # Special handling for fallback case
            if is_fallback and mx_host == domain and 'a_records' in locals():
                ip_data["ipv4"].extend(a_records)
                mx_ip_mapping.append({
                    "mx_host": domain, 
                    "ipv4": a_records,
                    "ipv6": [],
                    "is_fallback": True
                })
                continue
                
            # Structure to store IPs for this MX host
            mx_ips = {"mx_host": mx_host, "ipv4": [], "ipv6": []}
                
            # --- IPv4 Resolution ---
            ipv4_cache_key = CacheKeys.ip_address(mx_host, "ipv4")
            cached_ipv4 = cache_manager.get(ipv4_cache_key)
            
            if cached_ipv4:
                logger.debug(f"[{trace_id}] Cache hit for {mx_host} IPv4 addresses")
                ip_data["ipv4"].extend(cached_ipv4)
                mx_ips["ipv4"] = cached_ipv4
            else:
                try:
                    with EnhancedOperationTimer("ipv4_resolution", metadata={"host": mx_host}) as timer:
                        answers = dns.resolver.resolve(mx_host, 'A')
                        ipv4_list = [str(rdata) for rdata in answers]
                        
                        if ipv4_list:
                            cache_manager.set(ipv4_cache_key, ipv4_list, ttl=3600)
                            ip_data["ipv4"].extend(ipv4_list)
                            mx_ips["ipv4"] = ipv4_list
                            logger.debug(f"[{trace_id}] Resolved {mx_host} to {len(ipv4_list)} IPv4 addresses")
                except Exception as e:
                    logger.debug(f"[{trace_id}] No IPv4 addresses for {mx_host}: {str(e)}")
                
            # --- IPv6 Resolution ---
            ipv6_cache_key = CacheKeys.ip_address(mx_host, "ipv6")
            cached_ipv6 = cache_manager.get(ipv6_cache_key)
            
            if cached_ipv6:
                logger.debug(f"[{trace_id}] Cache hit for {mx_host} IPv6 addresses")
                ip_data["ipv6"].extend(cached_ipv6)
                mx_ips["ipv6"] = cached_ipv6
            else:
                try:
                    with EnhancedOperationTimer("ipv6_resolution", metadata={"host": mx_host}) as timer:
                        answers = dns.resolver.resolve(mx_host, 'AAAA')
                        # Convert to full expanded IPv6 format
                        ipv6_list = [ipaddress.IPv6Address(str(rdata)).exploded for rdata in answers]
                        
                        if ipv6_list:
                            cache_manager.set(ipv6_cache_key, ipv6_list, ttl=3600)
                            ip_data["ipv6"].extend(ipv6_list)
                            mx_ips["ipv6"] = ipv6_list
                            logger.debug(f"[{trace_id}] Resolved {mx_host} to {len(ipv6_list)} IPv6 addresses")
                except Exception as e:
                    logger.debug(f"[{trace_id}] No IPv6 addresses for {mx_host}: {str(e)}")
            
            # Record both IPv4 and IPv6 in the mapping
            mx_ip_mapping.append(mx_ips)
            
            # Record rate limit usage
            rate_limit_manager.record_usage('dns', mx_host)
        
        # --- IP Geolocation ---
        # Get geolocation data for the first few IPs
        geo_processed = set()  # Track which IPs we've already processed

        # Ensure infra_info is defined before use in geolocation
        infra_info = {
            "providers": [],
            "countries": [],
            "ptr_records": [],
            "whois_data": {}
        }
        
        # Process IPv4 addresses
        for ip in ip_data["ipv4"][:5]:  # Limit to first 5 IPs
            if ip in geo_processed:
                continue
                
            geo_cache_key = CacheKeys.geo_info(ip)
            cached_geo = cache_manager.get(geo_cache_key)
            
            if cached_geo:
                logger.debug(f"[{trace_id}] Cache hit for {ip} geolocation")
                ip_data["geo"][ip] = cached_geo
            else:
                try:
                    with EnhancedOperationTimer("geo_lookup", metadata={"ip": ip}) as timer:
                        # Try to determine country from IP
                        geo_info = get_ip_geolocation(ip, trace_id)
                        
                        if geo_info:
                            cache_manager.set(geo_cache_key, geo_info, ttl=86400*7)  # 7 day TTL
                            ip_data["geo"][ip] = geo_info
                            
                            # Add to infrastructure country list if not already there
                            if "country" in geo_info and geo_info["country"]:
                                if geo_info["country"] not in infra_info["countries"]:
                                    infra_info["countries"].append(geo_info["country"])
                except Exception as e:
                    logger.debug(f"[{trace_id}] Failed to get geolocation for {ip}: {e}")
            
            geo_processed.add(ip)
        
        # Process some IPv6 addresses too
        for ip in ip_data["ipv6"][:2]:  # Limit to first 2 IPv6 addresses
            if ip in geo_processed:
                continue
                
            geo_cache_key = CacheKeys.geo_info(ip)
            cached_geo = cache_manager.get(geo_cache_key)
            
            if cached_geo:
                logger.debug(f"[{trace_id}] Cache hit for {ip} geolocation")
                ip_data["geo"][ip] = cached_geo
            else:
                try:
                    with EnhancedOperationTimer("geo_lookup", metadata={"ip": ip}) as timer:
                        # Try to determine country from IP
                        geo_info = get_ip_geolocation(ip, trace_id)
                        
                        if geo_info:
                            cache_manager.set(geo_cache_key, geo_info, ttl=86400*7)
                            ip_data["geo"][ip] = geo_info
                            
                            # Add to country list if not already there
                            if "country" in geo_info and geo_info["country"]:
                                if geo_info["country"] not in infra_info["countries"]:
                                    infra_info["countries"].append(geo_info["country"])
                except Exception as e:
                    logger.debug(f"[{trace_id}] Failed to get geolocation for {ip}: {e}")
            
            geo_processed.add(ip)
    
    # After IP resolution, enhance with additional infrastructure info
    infra_info = {
        "providers": [],
        "countries": [],
        "ptr_records": [],
        "whois_data": {}
    }
    
    # Process IP addresses and MX hosts for infrastructure information
    if exchanges and ip_data["ipv4"]:
        # 1. Detect hosting providers from domains and subdomains
        provider_patterns = {
            "google": r'(google|googlemail|gmail|googleusercontent|goog)\.com',
            "microsoft": r'(microsoft|outlook|hotmail|office365|live|msn)\.com',
            "amazon": r'(aws|amazon|amazonses|amazonaws)\.com',
            "zoho": r'zoho\.com',
            "proton": r'(proton|protonmail)\.ch',
            "yahoo": r'yahoo\.',
            "cloudflare": r'cloudflare\.',
            "godaddy": r'godaddy\.',
            "namecheap": r'namecheap\.',
        }
        
        # Check for provider patterns in MX exchanges
        for mx_host in exchanges:
            for provider, pattern in provider_patterns.items():
                if re.search(pattern, mx_host, re.IGNORECASE):
                    if provider not in infra_info["providers"]:
                        infra_info["providers"].append(provider)
                        logger.debug(f"[{trace_id}] Detected provider: {provider} from {mx_host}")
        
        # 2. Perform reverse DNS lookups for each IP
        for idx, ip in enumerate(ip_data["ipv4"][:5]):  # Limit to first 5 IPs to avoid excessive lookups
            try:
                # Check cache for reverse DNS
                ptr_cache_key = CacheKeys.ptr_record(ip)
                cached_ptr = cache_manager.get(ptr_cache_key)
                
                if cached_ptr:
                    ptr_record = cached_ptr
                    logger.debug(f"[{trace_id}] Cache hit for PTR record of {ip}")
                else:
                    # Try to perform reverse DNS lookup
                    with EnhancedOperationTimer("ptr_lookup", metadata={"ip": ip}) as timer:
                        # Use socket.gethostbyaddr() which does reverse DNS lookup
                        try:
                            hostname, aliases, addresses = socket.gethostbyaddr(ip)
                            ptr_record = hostname
                        except (socket.herror, socket.gaierror):
                            # Alternative method using dns.resolver
                            try:
                                addr = dns.reversename.from_address(ip)
                                answers = dns.resolver.resolve(addr, 'PTR')
                                ptr_record = str(answers[0]).rstrip('.')
                            except Exception:
                                ptr_record = None
                    
                    # Cache PTR record if found
                    if ptr_record:
                        cache_manager.set(ptr_cache_key, ptr_record, ttl=86400)  # 24h TTL
                
                if ptr_record:
                    infra_info["ptr_records"].append({
                        "ip": ip,
                        "ptr": ptr_record
                    })
                    logger.debug(f"[{trace_id}] Resolved PTR for {ip}: {ptr_record}")
                    
                    # Check provider patterns in PTR records as well
                    for provider, pattern in provider_patterns.items():
                        if re.search(pattern, ptr_record, re.IGNORECASE):
                            if provider not in infra_info["providers"]:
                                infra_info["providers"].append(provider)
                                logger.debug(f"[{trace_id}] Detected provider from PTR: {provider}")
                
            except Exception as e:
                logger.warning(f"[{trace_id}] Failed to get PTR for {ip}: {str(e)}")
        
        # 3. Basic IP geolocation
        # This is simplified - in production you might use a proper IP geolocation service
        for ip in ip_data["ipv4"][:5]:  # Limit to first 5 IPs
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    continue
                    
                # Check if it's in a known range
                # This is a minimal implementation - would be better with a proper IP database
                if ip.startswith('13.'):
                    if "AWS" not in infra_info["providers"]:
                        infra_info["providers"].append("AWS")
                elif ip.startswith('104.'):
                    if "Cloudflare" not in infra_info["providers"]:
                        infra_info["providers"].append("Cloudflare")
                elif ip.startswith('8.8.'):
                    if "Google" not in infra_info["providers"]:
                        infra_info["providers"].append("Google")
                        
            except ValueError:
                continue
        
        # 4. WHOIS information for the primary domain
        # Note: Use a library that respects rate limits and has proper caching
        try:
            whois_info = {}
            whois_cache_key = CacheKeys.whois_info(domain)
            cached_whois = cache_manager.get(whois_cache_key)
            
            if cached_whois:
                whois_info = cached_whois
                logger.debug(f"[{trace_id}] Cache hit for WHOIS info of {domain}")
            else:
                with EnhancedOperationTimer("whois_lookup", metadata={"domain": domain}) as timer:
                    try:
                        # Try python-whois first
                        whois_info = {}
                        w = whois.whois(domain)
                        
                        # Extract key information
                        if w:
                            whois_info = {
                                "registrar": w.registrar,
                                "creation_date": w.creation_date,
                                "expiration_date": w.expiration_date,
                                "organization": w.org,
                                "country": w.country,
                                "emails": w.emails
                            }
                            
                            # Clean up None values and convert dates to strings
                            for key, value in whois_info.items():
                                if isinstance(value, (list, tuple)) and value and isinstance(value[0], datetime):
                                    whois_info[key] = str(value[0])
                                elif isinstance(value, datetime):
                                    whois_info[key] = str(value)
                                elif value is None:
                                    whois_info[key] = ""
                    
                    except Exception as e:
                        # Fallback to command line whois for more reliable results
                        # Note: This requires 'whois' to be installed on the system
                        try:
                            result = subprocess.run(['whois', domain], 
                                                  capture_output=True, 
                                                  text=True, 
                                                  timeout=5)
                            if result.returncode == 0:
                                raw_data = result.stdout
                                # Simple parsing of whois output
                                whois_info = {
                                    "raw": raw_data[:500]  # Limit size for storage
                                }
                                
                                # Extract key fields
                                patterns = {
                                    "registrar": r"Registrar:\s*(.+)",
                                    "organization": r"Registrant Organization:\s*(.+)",
                                    "country": r"Registrant Country:\s*(.+)",
                                    "creation_date": r"Creation Date:\s*(.+)",
                                    "expiration_date": r"Registry Expiry Date:\s*(.+)"
                                }
                                
                                for key, pattern in patterns.items():
                                    match = re.search(pattern, raw_data)
                                    if match:
                                        whois_info[key] = match.group(1).strip()
                        except Exception:
                            whois_info = {"error": "WHOIS lookup failed"}
                
                if whois_info:
                    cache_manager.set(whois_cache_key, whois_info, ttl=86400 * 7)  # 7-day TTL
            
            infra_info["whois_data"] = whois_info
            
            # Extract country information
            country = whois_info.get("country", "")
            if country and country not in infra_info["countries"]:
                infra_info["countries"].append(country)
                
        except Exception as e:
            logger.warning(f"[{trace_id}] WHOIS lookup failed for {domain}: {str(e)}")
    
    # Detect email provider from MX records
    email_provider_info = None
    if exchanges:
        email_provider_info = get_email_provider_info(exchanges, domain, trace_id)

    # Update the result dictionary
    result_dict = {
        "valid": bool(mx_records),
        "error": mx_result.get("error") if not is_fallback else None,
        "records": mx_records,
        "mx_record": exchanges[0] if exchanges else "",
        "preferences": preferences,
        "ip_addresses": {
            "ipv4": ip_data["ipv4"],
            "ipv6": ip_data["ipv6"],
            "geo": ip_data["geo"]
        },
        "mx_ip_mapping": mx_ip_mapping,
        "has_mx": bool(mx_records) and not is_fallback,
        "used_fallback": is_fallback,
        "mx_infrastructure": {
            "primary": primary_mx,
            "backups": backup_mx,
            "load_balanced": any(len(servers) > 1 for servers in mx_groups.values()),
            "has_failover": len(mx_groups) > 1
        },
        "infrastructure_info": infra_info,
        "email_provider": email_provider_info,  # Add the email provider information
        "execution_time": mx_result.get("duration_ms", 0)
    }
    
    return result_dict

def get_ip_geolocation(ip, trace_id=None):
    """
    Get geolocation information for an IP address.
    
    Args:
        ip: IP address to look up
        trace_id: Optional trace ID for logging
        
    Returns:
        Dict with geolocation information or None if lookup failed
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Skip private IPs
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return None
        
        # First, try known IP ranges for common providers
        # This is a minimal approach - consider using MaxMind GeoIP or ip-api for production
        geo = {"provider": "", "country": "", "region": ""}
        
        # IPv4 common ranges
        if isinstance(ip_obj, ipaddress.IPv4Address):
            ip_str = str(ip_obj)
            if ip_str.startswith('13.'):
                geo["provider"] = "AWS"
                geo["country"] = "US"
            elif ip_str.startswith('104.'):
                geo["provider"] = "Cloudflare"
                geo["country"] = "US"
            elif ip_str.startswith('8.8.'):
                geo["provider"] = "Google"
                geo["country"] = "US"
            elif ip_str.startswith('157.'):
                geo["provider"] = "Microsoft Azure"
                geo["country"] = "US"
            elif ip_str.startswith('185.'):
                # European ranges often start with 185
                geo["provider"] = "European Provider"
                geo["region"] = "Europe"
        # Handle IPv6 with special ranges
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            # Store full expanded IPv6 format
            ip_str = ip_obj.exploded
            if ip_str.startswith('2001:4860'):
                geo["provider"] = "Google"
            elif ip_str.startswith('2a00:1450'):
                geo["provider"] = "Google (Europe)"
            elif ip_str.startswith('2606:4700'):
                geo["provider"] = "Cloudflare"
            elif ip_str.startswith('2600:1f'):
                geo["provider"] = "AWS"
                
        # If nothing matched in our basic checks, try ip-api (free tier)
        if not geo["country"]:
            try:
                import requests
                response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,isp", 
                                      timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        geo = {
                            "provider": data.get("isp", "Unknown"),
                            "country": data.get("countryCode", "Unknown"),
                            "region": data.get("regionName", "Unknown")
                        }
            except Exception as e:
                logger.debug(f"[{trace_id}] IP API lookup failed for {ip}: {e}")
        
        return geo
    
    except Exception as e:
        logger.debug(f"[{trace_id}] Geolocation error for {ip}: {e}")
        return None

def get_email_provider_info(mx_exchanges, domain, trace_id=None):
    """
    Simple placeholder for provider info - actual data comes from email_provider_mapping view.
    
    Args:
        mx_exchanges: List of MX exchange hostnames
        domain: The domain being analyzed
        trace_id: Optional trace ID for logging
        
    Returns:
        Dict with minimal email provider information
    """
    # Check for custom hosted email (same domain in MX)
    uses_self_hosted = any(domain.lower() in mx.lower() for mx in mx_exchanges)
    
    # Simplified result structure - provider name will be populated from mx_ip_addresses table later
    return {
        "provider_name": "Unknown",
        "self_hosted": uses_self_hosted,
        "provider_detected": False
    }

def fetch_whois_info(context):
    """
    Retrieve WHOIS information for the domain of an email address.
    
    Args:
        context: Dictionary containing email address and trace_id
        
    Returns:
        Dict with WHOIS information for the domain
    """
    email = context.get("email", "")
    trace_id = context.get("trace_id", "")
    
    if not email or '@' not in email:
        return {
            "valid": False, 
            "error": "Invalid email format, cannot extract domain",
            "whois_info": None
        }
    
    # Extract domain from email
    domain = email.split('@')[1].strip().lower()
    
    # Check cache for WHOIS info
    whois_cache_key = CacheKeys.whois_info(domain)
    cached_whois = cache_manager.get(whois_cache_key)
    
    if cached_whois:
        logger.debug(f"[{trace_id}] Cache hit for WHOIS info of {domain}")
        return {
            "valid": True,
            "domain": domain,
            "whois_info": cached_whois,
            "source": "cache"
        }
    
    try:
        with EnhancedOperationTimer("whois_lookup", metadata={"domain": domain}) as timer:
            # Try python-whois first
            whois_info = {}
            
            try:
                w = whois.whois(domain)
                
                # Extract key information
                if w:
                    whois_info = {
                        "registrar": w.registrar,
                        "creation_date": w.creation_date,
                        "expiration_date": w.expiration_date,
                        "organization": w.org,
                        "country": w.country,
                        "emails": w.emails
                    }
                    
                    # Clean up None values and convert dates to strings
                    for key, value in whois_info.items():
                        if isinstance(value, (list, tuple)) and value and isinstance(value[0], datetime):
                            whois_info[key] = str(value[0])
                        elif isinstance(value, datetime):
                            whois_info[key] = str(value)
                        elif value is None:
                            whois_info[key] = ""
            
            except Exception as e:
                # Fallback to command line whois for more reliable results
                # Note: This requires 'whois' to be installed on the system
                logger.debug(f"[{trace_id}] Python-whois failed for {domain}: {str(e)}. Falling back to command line.")
                try:
                    import subprocess
                    result = subprocess.run(['whois', domain], 
                                          capture_output=True, 
                                          text=True, 
                                          timeout=5)
                    if result.returncode == 0:
                        raw_data = result.stdout
                        # Simple parsing of whois output
                        whois_info = {
                            "raw": raw_data[:500]  # Limit size for storage
                        }
                        
                        # Extract key fields
                        patterns = {
                            "registrar": r"Registrar:\s*(.+)",
                            "organization": r"Registrant Organization:\s*(.+)",
                            "country": r"Registrant Country:\s*(.+)",
                            "creation_date": r"Creation Date:\s*(.+)",
                            "expiration_date": r"Registry Expiry Date:\s*(.+)"
                        }
                        
                        for key, pattern in patterns.items():
                            match = re.search(pattern, raw_data)
                            if match:
                                whois_info[key] = match.group(1).strip()
                except Exception as sub_e:
                    logger.warning(f"[{trace_id}] Command-line whois also failed for {domain}: {str(sub_e)}")
                    whois_info = {"error": "WHOIS lookup failed with all methods"}
            
            # Cache the result with appropriate TTL from rate limit manager
            if whois_info:
                try:
                    from src.managers.rate_limit import rate_limit_manager
                    ttl = rate_limit_manager.get_cache_limit('whois_cache_ttl')
                except Exception:
                    # Default to 7 days if rate limit manager fails
                    ttl = 604800  # 7 days in seconds
                    
                cache_manager.set(whois_cache_key, whois_info, ttl=ttl)
            
            domain_age = None
            if "creation_date" in whois_info and whois_info["creation_date"]:
                try:
                    # Try to parse the creation date if it's a string
                    if isinstance(whois_info["creation_date"], str):
                        creation_date = parse(whois_info["creation_date"])
                        domain_age = (now_utc() - creation_date).days
                except Exception:
                    pass
            
            return {
                "valid": True,
                "domain": domain,
                "whois_info": whois_info,
                "domain_age_days": domain_age,
                "source": "lookup",
                "execution_time": timer.elapsed_ms
            }
    except Exception as e:
        logger.warning(f"[{trace_id}] WHOIS lookup failed for {domain}: {str(e)}")
        return {
            "valid": False,
            "error": f"WHOIS lookup failed: {str(e)}",
            "domain": domain,
            "whois_info": None
        }