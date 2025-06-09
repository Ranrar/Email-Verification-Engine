"""
Email Verification Engine - SPF (Sender Policy Framework) Validation
====================================================================
Implements RFC 7208 compliant SPF record validation.

SPF Check Process:
1. Extract domain from sender email
2. Fetch SPF record from DNS TXT records
3. Parse SPF mechanisms and modifiers
4. Evaluate mechanisms in order with DNS lookup tracking
5. Return SPF result with detailed analysis

Supported SPF Results:
- pass: IP is authorized to send
- fail: IP is not authorized to send  
- softfail: IP is probably not authorized
- neutral: no definitive statement
- none: no SPF record found
- permerror: permanent error (syntax, >10 lookups)
- temperror: temporary DNS error
"""

import ipaddress
import time
import dns.resolver
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import timedelta

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager
from src.managers.port import port_manager
from src.managers.time import EnhancedOperationTimer, now_utc, from_iso8601
from src.managers.log import Axe
from src.engine.functions.statistics import DNSServerStats
from src.engine.functions.mx import MXCacher

# Initialize logging
logger = Axe()

@dataclass
class SPFMechanism:
    """Represents a parsed SPF mechanism"""
    qualifier: str = "+"  # +, -, ~, ?
    mechanism: str = ""   # ip4, ip6, a, mx, include, ptr, exists, all
    value: str = ""       # The value after the colon (if any)
    original: str = ""    # Original mechanism string

@dataclass
class SPFModifier:
    """Represents a parsed SPF modifier"""
    name: str = ""        # redirect, exp
    value: str = ""       # The value after the equals sign
    original: str = ""    # Original modifier string

@dataclass
class SPFRecord:
    """Represents a parsed SPF record"""
    version: str = "spf1"
    mechanisms: List[SPFMechanism] = field(default_factory=list)
    modifiers: List[SPFModifier] = field(default_factory=list)
    raw_record: str = ""
    domain: str = ""
    
    def has_redirect(self) -> bool:
        """Check if record has redirect modifier"""
        return any(mod.name == "redirect" for mod in self.modifiers)
    
    def get_redirect_domain(self) -> Optional[str]:
        """Get redirect domain if present"""
        for mod in self.modifiers:
            if mod.name == "redirect":
                return mod.value
        return None
    
    def get_exp_domain(self) -> Optional[str]:
        """Get explanation domain if present"""
        for mod in self.modifiers:
            if mod.name == "exp":
                return mod.value
        return None

@dataclass
class SPFResult:
    """SPF evaluation result"""
    result: str = "none"           # pass, fail, softfail, neutral, none, permerror, temperror
    reason: str = ""               # Human readable reason
    mechanism_matched: str = ""    # Which mechanism matched
    dns_lookups: int = 0          # Number of DNS lookups performed
    explanation: str = ""          # Optional explanation text
    domain: str = ""              # Domain that was checked
    record: str = ""              # Raw SPF record
    processing_time_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    dns_lookup_log: List[Dict[str, Union[str, int]]] = field(default_factory=list)  # Add this field

class SPFValidator:
    """
    SPF record validator implementing RFC 7208
    """
    
    def __init__(self):
        """Initialize with required managers"""
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        
        # SPF specific settings with fallback defaults
        try:
            self.max_dns_lookups = self.rate_limit_manager.get_spf_max_lookups()
            # Ensure we have a reasonable default if the config returns 0 or None
            if not self.max_dns_lookups or self.max_dns_lookups <= 0:
                self.max_dns_lookups = 10  # RFC 7208 default
        except Exception as e:
            logger.warning(f"Failed to get SPF max lookups from rate limit manager: {e}, using default")
            self.max_dns_lookups = 10  # RFC 7208 default
        
        try:
            self.dns_timeout = self.dns_manager.get_timeout()
            if not self.dns_timeout or self.dns_timeout <= 0:
                self.dns_timeout = 5.0  # Default 5 seconds
        except Exception as e:
            logger.warning(f"Failed to get DNS timeout: {e}, using default")
            self.dns_timeout = 5.0
        
        try:
            self.spf_cache_ttl = self.rate_limit_manager.get_spf_cache_ttl()
            if not self.spf_cache_ttl or self.spf_cache_ttl <= 0:
                self.spf_cache_ttl = 3600  # Default 1 hour
        except Exception as e:
            logger.warning(f"Failed to get SPF cache TTL: {e}, using default")
            self.spf_cache_ttl = 3600
        
        # Qualifiers mapping
        self.qualifier_results = {
            '+': 'pass',
            '-': 'fail', 
            '~': 'softfail',
            '?': 'neutral'
        }
        
        logger.debug(f"SPF Validator initialized - Max lookups: {self.max_dns_lookups}, "
                    f"Timeout: {self.dns_timeout}s, Cache TTL: {self.spf_cache_ttl}s")
    
    def validate_spf(self, ip: str, sender: str, helo: Optional[str] = None, trace_id: Optional[str] = None) -> SPFResult:
        """
        Validate SPF for given parameters
        
        Args:
            ip: IP address of the sender
            sender: Envelope sender address (MAIL FROM)
            helo: HELO/EHLO domain (optional)
            trace_id: Optional trace ID for logging
            
        Returns:
            SPFResult with validation outcome
        """
        start_time = time.time()
        
        # Validate input parameters
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return SPFResult(
                result="permerror",
                reason="Invalid IP address format",
                errors=[f"Invalid IP address: {ip}"],
                processing_time_ms=(time.time() - start_time) * 1000
            )
        
        # Extract domain from sender
        if not sender or '@' not in sender:
            return SPFResult(
                result="permerror", 
                reason="Invalid sender address format",
                errors=[f"Invalid sender address: {sender}"],
                processing_time_ms=(time.time() - start_time) * 1000
            )
        
        domain = sender.split('@')[-1].lower().strip()
        
        logger.info(f"[{trace_id}] Starting SPF validation for IP {ip}, sender {sender}, domain {domain}")
        
        # Initialize lookup counter
        dns_lookups = 0
        
        try:
            # Get SPF record
            spf_record, lookup_count = self._get_spf_record(domain, trace_id)
            dns_lookups += lookup_count
            
            if not spf_record:
                result = SPFResult(
                    result="none",
                    reason="No SPF record found",
                    domain=domain,
                    dns_lookups=dns_lookups,
                    processing_time_ms=(time.time() - start_time) * 1000
                )
                logger.info(f"[{trace_id}] SPF result: none (no record found for {domain})")
                return result
            
            # Parse SPF record
            parsed_record = self._parse_spf_record(spf_record, domain)
            
            # Evaluate SPF record
            result = self._evaluate_spf_record(
                parsed_record, ip_obj, sender, helo, dns_lookups, trace_id
            )
            
            result.processing_time_ms = (time.time() - start_time) * 1000
            
            logger.info(f"[{trace_id}] SPF validation completed: {result.result} "
                       f"({result.reason}) in {result.processing_time_ms:.2f}ms")
            
            return result
            
        except Exception as e:
            logger.error(f"[{trace_id}] SPF validation error: {str(e)}")
            return SPFResult(
                result="temperror",
                reason=f"SPF validation error: {str(e)}",
                domain=domain,
                dns_lookups=dns_lookups,
                errors=[str(e)],
                processing_time_ms=(time.time() - start_time) * 1000
            )
    
    def _get_spf_record(self, domain: str, trace_id: Optional[str] = None) -> Tuple[Optional[str], int]:
        """
        Get SPF record from DNS TXT records using centralized DNS manager
        """
        # Check cache first
        cache_key = CacheKeys.spf(domain)
        cached_spf = cache_manager.get(cache_key)
        
        if cached_spf:
            expires_at = cached_spf.get('expires_at')
            if expires_at:
                expires_datetime = from_iso8601(expires_at)
                if expires_datetime and expires_datetime > now_utc():
                    logger.debug(f"[{trace_id}] Cache hit for SPF record of {domain}")
                    return cached_spf.get('record'), 0
            logger.debug(f"[{trace_id}] Expired cache entry for {domain}")
        
        # Check rate limits
        is_exceeded, limit_info = self.rate_limit_manager.check_rate_limit('dns', domain, 'txt_lookup')
        if is_exceeded:
            backoff_time = min(limit_info.get('backoff_seconds', 5), 30)
            logger.warning(f"[{trace_id}] Rate limit exceeded for {domain}, backing off for {backoff_time}s")
            raise Exception(f"Rate limit exceeded for {domain}")
        
        try:
            with EnhancedOperationTimer("spf_dns_lookup", metadata={"domain": domain}) as timer:
                # Use the centralized DNS manager which handles:
                # - IPv4/IPv6 preference
                # - Nameserver selection from database
                # - Performance optimization
                # - Error handling and stats
                answers = self.dns_manager.resolve(domain, 'TXT')
                
                spf_record = None
                spf_records = []
                
                # Look for SPF record in TXT records
                for rdata in answers:
                    txt_data = str(rdata).strip().strip('"')
                    
                    # Clean up the TXT data
                    if txt_data.startswith('"') and txt_data.endswith('"'):
                        txt_data = txt_data[1:-1]
                    
                    # Handle multiple quoted strings (concatenate them)
                    if '" "' in txt_data:
                        txt_data = txt_data.replace('" "', '')
                    
                    # Handle escaped quotes and other malformed content
                    txt_data = txt_data.replace('\\"', '"')
                    txt_data = txt_data.strip()
                    
                    # Validate that this looks like a legitimate TXT record
                    if not txt_data or len(txt_data) > 512:
                        logger.debug(f"[{trace_id}] Skipping invalid TXT record for {domain}: too long or empty")
                        continue
                    
                    logger.debug(f"[{trace_id}] Cleaned TXT record for {domain}: '{txt_data}'")
                    
                    # Check if this is an SPF record
                    if txt_data.lower().startswith('v=spf1'):
                        spf_records.append(txt_data)
                
                # RFC 7208: Multiple SPF records is an error
                if len(spf_records) > 1:
                    logger.warning(f"[{trace_id}] Multiple SPF records found for {domain}")
                    cache_data = {'record': None, 'error': 'Multiple SPF records'}
                    cache_manager.set(cache_key, cache_data, ttl=self.spf_cache_ttl)
                    raise Exception("Multiple SPF records found (RFC 7208 violation)")
                
                elif len(spf_records) == 1:
                    spf_record = spf_records[0]
                    logger.debug(f"[{trace_id}] Found SPF record for {domain}: {spf_record}")
                
                # Cache the result
                expiration = now_utc() + timedelta(seconds=self.spf_cache_ttl)
                cache_data = {
                    'record': spf_record, 
                    'timestamp': now_utc().isoformat(),
                    'expires_at': expiration.isoformat()
                }
                cache_manager.set(cache_key, cache_data, ttl=self.spf_cache_ttl)
                
                # Record rate limit usage
                self.rate_limit_manager.record_usage('dns', domain)
                
                return spf_record, 1  # 1 DNS lookup performed
                
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to get SPF record for {domain}: {str(e)}")
            raise
    
    def _parse_spf_record(self, spf_record: str, domain: str) -> SPFRecord:
        """
        Parse SPF record into mechanisms and modifiers
        
        Args:
            spf_record: Raw SPF record string
            domain: Domain the record belongs to
            
        Returns:
            Parsed SPFRecord object
        """
        record = SPFRecord(raw_record=spf_record, domain=domain)
        
        # Split record into terms
        terms = spf_record.split()
        
        for term in terms:
            term = term.strip()
            
            # Skip version
            if term.lower().startswith('v=spf1'):
                continue
            
            # Check if it's a modifier (contains =)
            if '=' in term and not term.startswith(('ip4:', 'ip6:', 'a:', 'mx:', 'include:', 'ptr:', 'exists:')):
                # This is a modifier
                if '=' in term:
                    name, value = term.split('=', 1)
                    modifier = SPFModifier(
                        name=name.lower(),
                        value=value,
                        original=term
                    )
                    record.modifiers.append(modifier)
            else:
                # This is a mechanism
                qualifier = '+'  # Default qualifier
                mechanism_text = term
                
                # Extract qualifier if present
                if term.startswith(('+', '-', '~', '?')):
                    qualifier = term[0]
                    mechanism_text = term[1:]
                
                # Parse mechanism
                if ':' in mechanism_text:
                    mechanism_name, mechanism_value = mechanism_text.split(':', 1)
                else:
                    mechanism_name = mechanism_text
                    mechanism_value = ""
                
                mechanism = SPFMechanism(
                    qualifier=qualifier,
                    mechanism=mechanism_name.lower(),
                    value=mechanism_value,
                    original=term
                )
                record.mechanisms.append(mechanism)
        
        return record
    
    def _evaluate_spf_record(self, record: SPFRecord, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, 
                           sender: str, helo: Optional[str], dns_lookups: int, trace_id: Optional[str] = None) -> SPFResult:
        """
        Evaluate SPF record mechanisms against the given IP
        
        Args:
            record: Parsed SPF record
            ip: IP address to check
            sender: Sender email address
            helo: HELO domain
            dns_lookups: Current DNS lookup count
            trace_id: Optional trace ID for logging
            
        Returns:
            SPFResult with evaluation outcome
        """
        # Track DNS lookups in this evaluation
        total_lookups = dns_lookups
        dns_lookup_log = []  # Add this to track lookup sources
        
        # Evaluate mechanisms in order
        for mechanism in record.mechanisms:
            
            # Check DNS lookup limit before each mechanism that might do lookups
            if mechanism.mechanism in ['a', 'mx', 'include', 'exists', 'ptr'] and total_lookups >= self.max_dns_lookups:
                return SPFResult(
                    result="permerror",
                    reason=f"Exceeded maximum DNS lookups ({self.max_dns_lookups})",
                    domain=record.domain,
                    record=record.raw_record,
                    dns_lookups=total_lookups,
                    errors=[f"DNS lookup limit exceeded at mechanism: {mechanism.original}"]
                )
            
            try:
                # Evaluate mechanism
                matches, lookups_used = self._evaluate_mechanism(
                    mechanism, ip, sender, helo, record.domain, trace_id
                )
                total_lookups += lookups_used
                if lookups_used > 0:
                    dns_lookup_log.append({
                        "mechanism": mechanism.original,
                        "lookups_used": lookups_used,
                        "total_so_far": total_lookups
                    })
                
                if matches:
                    # Mechanism matched - return result based on qualifier
                    result = self.qualifier_results.get(mechanism.qualifier, 'neutral')
                    
                    reason_map = {
                        'pass': f"IP {ip} is authorized by mechanism {mechanism.original}",
                        'fail': f"IP {ip} is not authorized by mechanism {mechanism.original}",
                        'softfail': f"IP {ip} is probably not authorized by mechanism {mechanism.original}",
                        'neutral': f"No definitive authorization for IP {ip} by mechanism {mechanism.original}"
                    }
                    
                    return SPFResult(
                        result=result,
                        reason=reason_map.get(result, f"Matched mechanism {mechanism.original}"),
                        mechanism_matched=mechanism.original,
                        domain=record.domain,
                        record=record.raw_record,
                        dns_lookups=total_lookups,
                        dns_lookup_log=dns_lookup_log  # Add this field to SPFResult
                    )
                    
            except Exception as e:
                logger.error(f"[{trace_id}] Error evaluating mechanism {mechanism.original}: {str(e)}")
                return SPFResult(
                    result="temperror",
                    reason=f"Error evaluating mechanism {mechanism.original}: {str(e)}",
                    domain=record.domain,
                    record=record.raw_record,
                    dns_lookups=total_lookups,
                    errors=[str(e)]
                )
        
        # No mechanisms matched - check for redirect
        if record.has_redirect():
            redirect_domain = record.get_redirect_domain()
            logger.debug(f"[{trace_id}] No mechanisms matched, following redirect to {redirect_domain}")
            
            # Check DNS lookup limit before redirect
            if total_lookups >= self.max_dns_lookups:
                return SPFResult(
                    result="permerror",
                    reason=f"Exceeded maximum DNS lookups ({self.max_dns_lookups}) before redirect",
                    domain=record.domain,
                    record=record.raw_record,
                    dns_lookups=total_lookups,
                    errors=["DNS lookup limit exceeded before redirect"]
                )
            
            # Ensure redirect domain is not None
            if not redirect_domain:
                return SPFResult(
                    result="permerror",
                    reason="Redirect modifier has no domain value",
                    domain=record.domain,
                    record=record.raw_record,
                    dns_lookups=total_lookups,
                    errors=["Redirect modifier missing domain value"]
                )
            
            # Recursively evaluate redirect domain
            try:
                redirect_record, redirect_lookups = self._get_spf_record(redirect_domain, trace_id)
                total_lookups += redirect_lookups
                
                if redirect_record:
                    parsed_redirect = self._parse_spf_record(redirect_record, redirect_domain)
                    return self._evaluate_spf_record(
                        parsed_redirect, ip, sender, helo, total_lookups, trace_id
                    )
                else:
                    return SPFResult(
                        result="permerror",
                        reason=f"Redirect domain {redirect_domain} has no SPF record",
                        domain=record.domain,
                        record=record.raw_record,
                        dns_lookups=total_lookups,
                        errors=[f"Redirect target {redirect_domain} has no SPF record"]
                    )
                    
            except Exception as e:
                logger.error(f"[{trace_id}] Error processing redirect to {redirect_domain}: {str(e)}")
                return SPFResult(
                    result="temperror",
                    reason=f"Error processing redirect to {redirect_domain}: {str(e)}",
                    domain=record.domain,
                    record=record.raw_record,
                    dns_lookups=total_lookups,
                    errors=[str(e)]
                )
        
        # No mechanisms matched and no redirect - result is neutral
        return SPFResult(
            result="neutral",
            reason="No mechanisms matched and no redirect specified",
            domain=record.domain,
            record=record.raw_record,
            dns_lookups=total_lookups
        )
    
    def _evaluate_mechanism(self, mechanism: SPFMechanism, ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      sender: str, helo: Optional[str], domain: str, trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """
        Evaluate a single SPF mechanism
        
        Args:
            mechanism: SPF mechanism to evaluate
            ip: IP address to check
            sender: Sender email address
            helo: HELO domain
            domain: Current SPF domain
            trace_id: Optional trace ID for logging
            
        Returns:
            Tuple of (matches: bool, dns_lookups_used: int)
        """
        mechanism_name = mechanism.mechanism.lower()
        
        if mechanism_name == 'all':
            # 'all' always matches
            return True, 0
        
        elif mechanism_name == 'ip4':
            # Check IPv4 address or network
            if isinstance(ip, ipaddress.IPv6Address):
                return False, 0
            
            try:
                if '/' in mechanism.value:
                    network = ipaddress.IPv4Network(mechanism.value, strict=False)
                    return ip in network, 0
                else:
                    target_ip = ipaddress.IPv4Address(mechanism.value)
                    return ip == target_ip, 0
            except ValueError:
                logger.warning(f"[{trace_id}] Invalid ip4 mechanism value: {mechanism.value}")
                return False, 0
    
        elif mechanism_name == 'ip6':
            # Check IPv6 address or network
            if isinstance(ip, ipaddress.IPv4Address):
                return False, 0
            
            try:
                if '/' in mechanism.value:
                    network = ipaddress.IPv6Network(mechanism.value, strict=False)
                    return ip in network, 0
                else:
                    target_ip = ipaddress.IPv6Address(mechanism.value)
                    return ip == target_ip, 0
            except ValueError:
                logger.warning(f"[{trace_id}] Invalid ip6 mechanism value: {mechanism.value}")
                return False, 0
    
        elif mechanism_name == 'a':
            # Check A/AAAA records
            target_domain = mechanism.value if mechanism.value else domain
            return self._check_a_record(target_domain, ip, trace_id)
        
        elif mechanism_name == 'mx':
            # Check MX records
            target_domain = mechanism.value if mechanism.value else domain
            return self._check_mx_record(target_domain, ip, trace_id)
        
        elif mechanism_name == 'include':
            # Include another SPF record
            if not mechanism.value:
                logger.warning(f"[{trace_id}] Include mechanism missing domain value")
                return False, 0
            
            return self._check_include(mechanism.value, ip, sender, helo, trace_id)
        
        elif mechanism_name == 'exists':
            # Check if domain exists
            if not mechanism.value:
                logger.warning(f"[{trace_id}] Exists mechanism missing domain value")
                return False, 0
            
            return self._check_exists(mechanism.value, trace_id)
        
        elif mechanism_name == 'ptr':
            # PTR record check (deprecated but supported)
            target_domain = mechanism.value if mechanism.value else domain
            return self._check_ptr_record(target_domain, ip, trace_id)
        
        else:
            logger.warning(f"[{trace_id}] Unknown SPF mechanism: {mechanism_name}")
            return False, 0
    
    def _check_a_record(self, domain: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, 
                   trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """Check if IP matches A/AAAA records for domain"""
        try:
            # Determine record type based on IP version
            record_type = 'A' if isinstance(ip, ipaddress.IPv4Address) else 'AAAA'
            
            answers = self.dns_manager.resolve(domain, record_type)
            
            for rdata in answers:
                try:
                    record_ip = ipaddress.ip_address(str(rdata))
                    if record_ip == ip:
                        return True, 1
                except ValueError:
                    continue
            
            return False, 1
            
        except Exception as e:
            logger.debug(f"[{trace_id}] A record check failed for {domain}: {str(e)}")
            return False, 1
    
    def _check_mx_record(self, domain: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                        trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """Check if IP matches any MX record IPs for domain using existing MX infrastructure""" 
        
        # Check cache first
        cache_key = f"spf_mx_check:{domain}:{ip}"
        cached_result = cache_manager.get(cache_key)
        if cached_result is not None:
            logger.debug(f"[{trace_id}] Cache hit for MX check {domain}:{ip}")
            return cached_result["matches"], 0
        
        try:
            # Use existing MX infrastructure instead of manual resolution
            from src.engine.functions.mx import fetch_mx_records
            
            mx_context = {"email": f"test@{domain}", "trace_id": trace_id}
            mx_result = fetch_mx_records(mx_context)
            
            # Count as one DNS lookup (the MX lookup)
            dns_lookups = 1
            
            if not mx_result.get("valid"):
                cache_manager.set(cache_key, {"matches": False}, ttl=300)
                return False, dns_lookups
            
            # Check if our IP matches any of the resolved MX IPs
            ip_addresses = mx_result.get("ip_addresses", {})
            all_ips = ip_addresses.get("ipv4", []) + ip_addresses.get("ipv6", [])
            
            for mx_ip_str in all_ips:
                try:
                    mx_ip = ipaddress.ip_address(mx_ip_str)
                    if mx_ip == ip:
                        cache_manager.set(cache_key, {"matches": True}, ttl=300)
                        logger.debug(f"[{trace_id}] SPF MX check: IP {ip} matches MX record IP {mx_ip}")
                        return True, dns_lookups
                except ValueError:
                    continue
            
            # No match found
            cache_manager.set(cache_key, {"matches": False}, ttl=300)
            return False, dns_lookups
            
        except Exception as e:
            logger.debug(f"[{trace_id}] MX record check failed for {domain}: {str(e)}")
            return False, 1
    
    def _check_include(self, include_domain: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                      sender: str, helo: Optional[str], trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """Check included SPF record"""
        try:
            # Get SPF record for included domain
            spf_record, lookups = self._get_spf_record(include_domain, trace_id)
            
            if not spf_record:
                return False, lookups
            
            # Parse and evaluate included record
            parsed_record = self._parse_spf_record(spf_record, include_domain)
            result = self._evaluate_spf_record(parsed_record, ip, sender, helo, lookups, trace_id)
            
            # Include only matches on 'pass' result
            matches = result.result == 'pass'
            return matches, result.dns_lookups
            
        except Exception as e:
            logger.debug(f"[{trace_id}] Include check failed for {include_domain}: {str(e)}")
            return False, 1
    
    def _check_exists(self, domain: str, trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """Check if domain exists (has any A record)"""
        try:
            answers = self.dns_manager.resolve(domain, 'A')
            return len(answers) > 0, 1
            
        except Exception as e:
            logger.debug(f"[{trace_id}] Exists check failed for {domain}: {str(e)}")
            return False, 1
    
    def _check_ptr_record(self, domain: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                        trace_id: Optional[str] = None) -> Tuple[bool, int]:
        """Check PTR record (deprecated mechanism)"""
        try:
            # Get PTR record for IP
            if isinstance(ip, ipaddress.IPv4Address):
                # For IPv4: reverse octets and add .in-addr.arpa
                octets = str(ip).split('.')
                ptr_name = '.'.join(reversed(octets)) + '.in-addr.arpa'
            else:
                expanded = ip.exploded.replace(':', '')
                nibbles = [expanded[i] for i in range(len(expanded))]
                ptr_name = '.'.join(reversed(nibbles)) + '.ip6.arpa'
            
            ptr_answers = self.dns_manager.resolve(ptr_name, 'PTR')
            dns_lookups = 1
            
            # Check if any PTR result matches or is subdomain of target domain
            for ptr_rdata in ptr_answers:
                ptr_domain = str(ptr_rdata).rstrip('.')
                
                if ptr_domain == domain or ptr_domain.endswith('.' + domain):
                    return True, dns_lookups
            
            return False, dns_lookups
            
        except Exception as e:
            logger.debug(f"[{trace_id}] PTR record check failed for {ip}: {str(e)}")
            return False, 1
    
    def _prefetch_dns_records(self, record: SPFRecord, trace_id: Optional[str] = None) -> Dict[str, Any]:
        """Prefetch DNS records for mechanisms that need them"""
        prefetch_results = {}
        lookup_count = 0
        
        # Collect domains to lookup
        mx_domains = []
        a_domains = []
        
        for mechanism in record.mechanisms:
            if mechanism.mechanism == 'mx':
                target = mechanism.value if mechanism.value else record.domain
                mx_domains.append(target)
            elif mechanism.mechanism == 'a':
                target = mechanism.value if mechanism.value else record.domain
                a_domains.append(target)
        
        # Batch lookup MX records
        for domain in mx_domains[:5]:  # Limit prefetch to avoid excessive lookups
            if lookup_count >= self.max_dns_lookups:
                break
                
            try:
                mx_result = self.dns_manager.resolve(domain, 'MX')
                prefetch_results[f"mx:{domain}"] = mx_result
                lookup_count += 1
            except Exception as e:
                logger.debug(f"[{trace_id}] Prefetch failed for MX:{domain}: {e}")
        
        # Return prefetch results and lookup count as a dictionary
        return {
            'prefetch_results': prefetch_results,
            'lookup_count': lookup_count
        }

def _extract_sender_ip_from_dns(email: str, trace_id: Optional[str] = None) -> Optional[str]:
    """
    Extract sender IP from DNS using existing MX infrastructure
    
    Args:
        email: Email address to extract domain from
        trace_id: Optional trace ID for logging
        
    Returns:
        IP address string or None if not available
    """
    try:
        # Extract domain from email
        if '@' not in email:
            return None
            
        domain = email.split('@')[-1].lower().strip()
        
        logger.debug(f"[{trace_id}] Extracting sender IP from DNS for domain: {domain}")
        
        # Use existing MX infrastructure instead of manual DNS resolution
        from src.engine.functions.mx import fetch_mx_records
        
        mx_context = {"email": email, "trace_id": trace_id}
        mx_result = fetch_mx_records(mx_context)
        
        # Check if domain exists
        if not mx_result.get("valid") and mx_result.get("error") == "Domain does not exist":
            logger.warning(f"[{trace_id}] Domain {domain} does not exist")
            return None
        
        # Extract IP addresses from MX result
        ip_addresses = mx_result.get("ip_addresses", {})
        
        # Prefer IPv4, fallback to IPv6
        ipv4_addresses = ip_addresses.get("ipv4", [])
        if ipv4_addresses:
            sender_ip = ipv4_addresses[0]
            logger.info(f"[{trace_id}] Found sender IP from MX infrastructure (IPv4): {sender_ip}")
            return sender_ip
        
        ipv6_addresses = ip_addresses.get("ipv6", [])
        if ipv6_addresses:
            sender_ip = ipv6_addresses[0]
            logger.info(f"[{trace_id}] Found sender IP from MX infrastructure (IPv6): {sender_ip}")
            return sender_ip
        
        # If no MX IPs found, try direct domain resolution
        dns_manager = DNSManager()
        
        # Try A record for domain
        try:
            answers = dns_manager.resolve(domain, 'A')
            if answers:
                sender_ip = str(answers[0])
                logger.info(f"[{trace_id}] Found sender IP from direct A record: {sender_ip}")
                return sender_ip
        except Exception as e:
            logger.debug(f"[{trace_id}] Failed to get A record for {domain}: {e}")
        
        # Try AAAA record for domain
        try:
            answers = dns_manager.resolve(domain, 'AAAA')
            if answers:
                sender_ip = str(answers[0])
                logger.info(f"[{trace_id}] Found sender IP from direct AAAA record: {sender_ip}")
                return sender_ip
        except Exception as e:
            logger.debug(f"[{trace_id}] Failed to get AAAA record for {domain}: {e}")
        
        # All methods failed
        logger.warning(f"[{trace_id}] No sender IP could be extracted from DNS for {domain}")
        return None
        
    except Exception as e:
        logger.error(f"[{trace_id}] Error extracting sender IP from DNS for {email}: {e}")
        return None

# Main SPF check function for the validation engine
def spf_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    SPF validation function for the Email Verification Engine
    
    Args:
        context: Dictionary containing:
            - email: Email address being validated
            - trace_id: Optional trace ID for logging
            - helo_domain: Optional HELO domain
    
    Returns:
        Dict with SPF validation results
    """
    email = context.get("email", "")
    trace_id = context.get("trace_id", "")
    helo_domain = context.get("helo_domain", "")
    
    if not email or '@' not in email:
        return {
            "valid": False,
            "error": "Invalid email format for SPF check",
            "spf_result": "permerror",
            "spf_record": None,
            "execution_time": 0
        }
    
    # Extract domain from email BEFORE using it
    domain = email.split('@')[-1].lower().strip()
    
    # Extract sender IP from DNS nameserver response
    sender_ip = _extract_sender_ip_from_dns(email, trace_id)
    
    # Hard fail if no sender IP is available from DNS
    if not sender_ip:
        logger.error(f"[{trace_id}] SPF validation failed: No sender IP available from DNS for {email}")
        return {
            "valid": False,
            "error": f"No sender IP available from DNS nameserver response for domain {domain} - SPF validation cannot proceed",
            "spf_result": "permerror",
            "spf_record": None,
            "spf_domain": domain,
            "execution_time": 0,
            "dns_lookups": 0,
            "dns_methods_tried": ["mx_records", "a_record", "aaaa_record"]

        }
    
    # Log the sender IP (only in logs, not returned to frontend)
    logger.info(f"[{trace_id}] Using sender IP from DNS for SPF validation: {sender_ip}")
    
    # Initialize SPF validator
    validator = SPFValidator()
    
    # Perform SPF validation
    start_time = time.time()
    try:
        spf_result = validator.validate_spf(sender_ip, email, helo_domain, trace_id)
        execution_time = (time.time() - start_time) * 1000
        
        return {
            "valid": spf_result.result == "pass",
            "spf_result": spf_result.result,
            "spf_record": spf_result.record,
            "spf_reason": spf_result.reason,
            "spf_mechanism_matched": spf_result.mechanism_matched,
            "spf_dns_lookups": spf_result.dns_lookups,
            "spf_explanation": spf_result.explanation,
            "spf_domain": spf_result.domain,
            "execution_time": execution_time,
            "errors": spf_result.errors,
            "warnings": spf_result.warnings,
            "dns_lookup_log": spf_result.dns_lookup_log
        }
    except Exception as e:
        execution_time = (time.time() - start_time) * 1000
        logger.error(f"[{trace_id}] SPF validation error: {str(e)}")
        return {
            "valid": False,
            "error": f"SPF validation error: {str(e)}",
            "spf_result": "temperror",
            "spf_record": None,
            "spf_domain": domain,  # Now domain is properly defined
            "execution_time": execution_time
        }
