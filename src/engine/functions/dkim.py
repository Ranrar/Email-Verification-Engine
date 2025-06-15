"""
Email Verification Engine - DKIM (DomainKeys Identified Mail) Validation
========================================================================
Implements RFC 6376 compliant DKIM record validation.

DKIM Check Process:
1. Query DNS for DKIM selector records
2. Parse DKIM public key records
3. Validate key format and parameters
4. Assess DKIM setup strength
5. Return DKIM status and recommendations

Note: This validates DKIM DNS public key records, not actual message signatures
(as we don't have email messages to verify signatures against).
"""

import time
import re
import base64
import binascii
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json

# Import managers from the Email Verification Engine
from src.managers.cache import cache_manager, CacheKeys
from src.managers.dns import DNSManager
from src.managers.rate_limit import RateLimitManager
from src.managers.log import get_logger
from src.managers.time import now_utc, EnhancedOperationTimer
from src.engine.functions.statistics import DNSServerStats
from src.helpers.dbh import sync_db

# Import trace system
from src.helpers.tracer import (
    ensure_trace_id,
    ensure_context_has_trace_id,
    trace_function,
    validate_trace_id,
    create_child_trace_id
)

# Initialize logging
logger = get_logger()

@dataclass
class DKIMRecord:
    """Represents a parsed DKIM record"""
    version: str = "DKIM1"
    key_type: str = "rsa"  # rsa, ed25519
    public_key: str = ""
    hash_algorithms: List[str] = field(default_factory=lambda: ["sha256"])
    service_types: List[str] = field(default_factory=lambda: ["*"])
    flags: List[str] = field(default_factory=list)
    notes: str = ""
    key_length: int = 0
    raw_record: str = ""
    selector: str = ""
    domain: str = ""
    created_at: datetime = field(default_factory=now_utc)
    testing: bool = False
    valid: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass 
class DKIMResult:
    """DKIM validation result"""
    domain: str = ""
    selector: str = ""
    has_dkim: bool = False
    key_type: str = ""
    key_length: int = 0
    hash_algorithms: List[str] = field(default_factory=list)
    service_types: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    testing: bool = False
    record_count: int = 0
    found_selectors: List[str] = field(default_factory=list)
    record: Optional[DKIMRecord] = None
    dns_lookups: int = 0
    execution_time_ms: float = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    security_level: str = "unknown"
    trace_id: Optional[str] = None

class DKIMValidator:
    """DKIM record validator implementing RFC 6376"""
    
    @trace_function("dkim_validator_init")
    def __init__(self, trace_id: Optional[str] = None):
        """Initialize with required managers"""
        self.trace_id = ensure_trace_id(trace_id)
        
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        
        # Common DKIM selectors to try
        self.common_selectors = [
            "default", "selector1", "selector2", "dkim", "mail", "email",
            "google", "s1", "s2", "k1", "key1", "20", "19", "18", "x"
        ]
        
        # Get cache TTL
        try:
            self.dkim_cache_ttl = self.rate_limit_manager.get_dkim_cache_ttl()
            if not self.dkim_cache_ttl or self.dkim_cache_ttl <= 0:
                self.dkim_cache_ttl = 3600
        except:
            self.dkim_cache_ttl = 3600
        
        # Get DNS timeout from DNS manager
        try:
            self.dns_timeout = self.dns_manager.get_timeout()
            if not self.dns_timeout or self.dns_timeout <= 0:
                self.dns_timeout = 5.0
        except:
            self.dns_timeout = 5.0
        
        # Initialize DNS stats if available
        try:
            self.dns_stats = DNSServerStats()
        except:
            self.dns_stats = None
        
        logger.debug(f"[{self.trace_id}] DKIM Validator initialized - Cache TTL: {self.dkim_cache_ttl}s, "
                    f"DNS Timeout: {self.dns_timeout}s")

    @trace_function("validate_dkim")
    def validate_dkim(self, domain: str, selector: Optional[str] = None, trace_id: Optional[str] = None) -> DKIMResult:
        """
        Validate DKIM records for a domain with enhanced timing and statistics
        
        Args:
            domain: Domain to validate
            selector: Optional DKIM selector (will autodetect if not provided)
            trace_id: Optional trace ID for logging
            
        Returns:
            DKIMResult with validation outcome
        """
        # Ensure we have a valid trace_id
        trace_id = ensure_trace_id(trace_id)
        
        # Validate trace_id at entry point
        if not validate_trace_id(trace_id):
            logger.error(f"Invalid trace_id received in validate_dkim: {trace_id}")
            trace_id = ensure_trace_id()
        
        with EnhancedOperationTimer(f"DKIM validation for {domain}") as timer:
            logger.info(f"[{trace_id}] Starting DKIM validation for domain {domain}")
            
            result = DKIMResult(domain=domain, trace_id=trace_id)
            
            # If no selector provided, try to discover active selectors
            if not selector:
                selectors, dns_lookups = self._discover_dkim_selectors(domain, trace_id)
                result.dns_lookups += dns_lookups
                result.found_selectors = selectors
                result.record_count = len(selectors)
                
                if selectors:
                    logger.info(f"[{trace_id}] Found {len(selectors)} DKIM selectors for {domain}: {', '.join(selectors)}")
                    # Use the first found selector
                    selector = selectors[0]
                else:
                    result.warnings.append(f"No DKIM selectors found for {domain}")
                    result.recommendations.append("Implement DKIM with a valid selector and key")
                    logger.info(f"[{trace_id}] No DKIM selectors found for {domain}")
                    result.execution_time_ms = timer.elapsed_ms or 0.0
                    return result
            
            # Store selector in result
            result.selector = selector if selector is not None else ""
            
            # Get DKIM record for the selector
            dkim_record, dns_lookups = self._get_dkim_record(domain, selector, trace_id)
            result.dns_lookups += dns_lookups
            
            if dkim_record:
                result.has_dkim = True
                result.record = dkim_record
                result.key_type = dkim_record.key_type
                result.key_length = dkim_record.key_length
                result.hash_algorithms = dkim_record.hash_algorithms
                result.service_types = dkim_record.service_types
                result.flags = dkim_record.flags
                result.testing = dkim_record.testing
                
                # Collect errors and warnings from record
                result.errors.extend(dkim_record.errors)
                result.warnings.extend(dkim_record.warnings)
                
                # Generate security assessment and recommendations
                result.security_level = self._assess_security_level(dkim_record, trace_id)
                result.recommendations = self._generate_recommendations(dkim_record, trace_id)
            else:
                result.warnings.append(f"No valid DKIM record found for selector '{selector}' at {domain}")
                result.recommendations.append("Implement DKIM with a valid selector and key")
            
            result.execution_time_ms = timer.elapsed_ms or 0.0
            
            # Record statistics
            self._record_dkim_statistics(result, trace_id)
            
            logger.info(f"[{trace_id}] DKIM validation completed for {domain}: "
                       f"has_dkim={result.has_dkim}, security={result.security_level}")
            
            return result

    @trace_function("discover_dkim_selectors")
    def _discover_dkim_selectors(self, domain: str, trace_id: str) -> Tuple[List[str], int]:
        """
        Discover active DKIM selectors for a domain
        
        Args:
            domain: Domain to check
            trace_id: Trace ID for logging
            
        Returns:
            Tuple of (list of active selectors, number of DNS lookups performed)
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _discover_dkim_selectors: {trace_id}")
            trace_id = ensure_trace_id()
        
        active_selectors = []
        dns_lookups = 0
        
        # Check cache first
        cache_key = f"dkim_selectors:{domain}"
        cached_selectors = cache_manager.get(cache_key)
        if cached_selectors:
            logger.debug(f"[{trace_id}] Cache hit for DKIM selectors of {domain}")
            return cached_selectors, 0
        
        logger.debug(f"[{trace_id}] Attempting to discover DKIM selectors for {domain}")
        
        # Check common selectors
        for selector in self.common_selectors:
            # Check rate limits (FIXED: removed trace_id parameter if it was being passed)
            is_exceeded, _ = self.rate_limit_manager.check_rate_limit('dns', domain, 'dkim_lookup')
            if is_exceeded:
                logger.warning(f"[{trace_id}] Rate limit exceeded for {domain} DKIM lookups")
                break
            
            try:
                # Construct DKIM DNS name
                dkim_domain = f"{selector}._domainkey.{domain}"
                logger.debug(f"[{trace_id}] Checking DKIM selector: {dkim_domain}")
                
                # Query TXT record
                answers = self.dns_manager.resolve(dkim_domain, 'TXT')
                dns_lookups += 1
                
                # Record rate limit usage
                self.rate_limit_manager.record_usage('dns', domain)

                if answers:
                    # Check for DKIM record (v=DKIM1)
                    for rdata in answers:
                        record_str = str(rdata).strip('"')
                        if record_str.startswith('v=DKIM1'):
                            active_selectors.append(selector)
                            logger.debug(f"[{trace_id}] Found active DKIM selector: {selector}")
                            break
            except Exception as e:
                logger.debug(f"[{trace_id}] Error checking DKIM selector {selector}: {str(e)}")
                continue
        
        # Cache the results
        cache_manager.set(cache_key, active_selectors, ttl=3600)  # 1 hour cache
        
        return active_selectors, dns_lookups

    @trace_function("get_dkim_record")
    def _get_dkim_record(self, domain: str, selector: str, trace_id: str) -> Tuple[Optional[DKIMRecord], int]:
        """
        Get DKIM record from DNS TXT records
        
        Args:
            domain: Domain to check
            selector: DKIM selector
            trace_id: Trace ID for logging
            
        Returns:
            Tuple of (parsed DKIM record or None if not found, number of DNS lookups performed)
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _get_dkim_record: {trace_id}")
            trace_id = ensure_trace_id()
        
        # Construct DKIM DNS name
        dkim_domain = f"{selector}._domainkey.{domain}"
        
        # Use centralized cache key
        cache_key = CacheKeys.dkim(dkim_domain)
        
        cached_result = cache_manager.get(cache_key)
        if cached_result is not None:
            logger.debug(f"[{trace_id}] Cache hit for DKIM record {dkim_domain}")
            return cached_result, 0
        
        try:
            logger.debug(f"[{trace_id}] Querying DKIM record for {dkim_domain}")
            
            # Check rate limits
            is_exceeded, _ = self.rate_limit_manager.check_rate_limit('dns', domain, 'dkim_lookup')
            if is_exceeded:
                logger.warning(f"[{trace_id}] Rate limit exceeded for {domain} DKIM lookup")
                raise Exception(f"Rate limit exceeded for {domain}")
            
            # Query TXT records
            txt_records = self.dns_manager.resolve(dkim_domain, 'TXT')
            
            # Record rate limit usage
            self.rate_limit_manager.record_usage('dns', domain)

            if not txt_records:
                cache_manager.set(cache_key, None, ttl=300)  # Cache negative results for 5 minutes
                return None, 1
            
            # Find DKIM record (should start with v=DKIM1)
            dkim_txt = None
            for record in txt_records:
                record_str = str(record).strip('"')
                if record_str.startswith('v=DKIM1'):
                    dkim_txt = record_str
                    break
            
            if not dkim_txt:
                cache_manager.set(cache_key, None, ttl=300)
                return None, 1
            
            # Parse DKIM record
            dkim_record = self._parse_dkim_record(dkim_txt, selector, domain, trace_id)
            
            # Cache result with proper TTL
            cache_manager.set(cache_key, dkim_record, ttl=self.dkim_cache_ttl)
            
            return dkim_record, 1
            
        except Exception as e:
            logger.debug(f"[{trace_id}] DKIM lookup failed for {dkim_domain}: {str(e)}")
            cache_manager.set(cache_key, None, ttl=300)
            return None, 1

    @trace_function("parse_dkim_record")
    def _parse_dkim_record(self, record: str, selector: str, domain: str, trace_id: str) -> DKIMRecord:
        """
        Parse DKIM TXT record
        
        Args:
            record: Raw DKIM record string
            selector: DKIM selector
            domain: Domain the record belongs to
            trace_id: Trace ID for logging
            
        Returns:
            Parsed DKIMRecord object
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _parse_dkim_record: {trace_id}")
            trace_id = ensure_trace_id()
        
        dkim_record = DKIMRecord(raw_record=record, selector=selector, domain=domain)
        
        try:
            logger.debug(f"[{trace_id}] Parsing DKIM record: {record}")
            
            # Parse tag-value pairs
            tags = {}
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    tags[key.strip()] = value.strip()
            
            # Extract version
            dkim_record.version = tags.get('v', 'DKIM1')
            
            # Extract public key
            public_key = tags.get('p', '')
            dkim_record.public_key = public_key
            
            # Check for revoked key (empty public key)
            if public_key == '':
                dkim_record.errors.append("Public key is empty (revoked)")
                dkim_record.valid = False
                return dkim_record
            
            # Extract key length
            key_length = self._extract_key_length(public_key, trace_id)
            dkim_record.key_length = key_length
            
            # Extract key type
            dkim_record.key_type = tags.get('k', 'rsa').lower()
            if dkim_record.key_type not in ['rsa', 'ed25519']:
                dkim_record.warnings.append(f"Unsupported key type: {dkim_record.key_type}")
            
            # Extract hash algorithms
            if 'h' in tags:
                dkim_record.hash_algorithms = [h.strip().lower() for h in tags['h'].split(':')]
            
            # Extract service types
            if 's' in tags:
                dkim_record.service_types = [s.strip().lower() for s in tags['s'].split(':')]
            
            # Extract flags
            if 't' in tags:
                dkim_record.flags = [f.strip().lower() for f in tags['t'].split(':')]
                
                # Check for testing flag
                if 'y' in dkim_record.flags:
                    dkim_record.testing = True
                    dkim_record.warnings.append("Key is in testing mode (t=y)")
            
            # Extract notes
            if 'n' in tags:
                dkim_record.notes = tags['n']
            
            # Validate key length
            if dkim_record.key_type == 'rsa':
                if key_length < 1024:
                    dkim_record.errors.append(f"RSA key length too short: {key_length} bits (should be at least 2048)")
                elif key_length < 2048:
                    dkim_record.warnings.append(f"RSA key length is weak: {key_length} bits (recommend at least 2048)")
            
            # Validate hash algorithms
            valid_hashes = ['sha1', 'sha256']
            for hash_algo in dkim_record.hash_algorithms:
                if hash_algo not in valid_hashes:
                    dkim_record.warnings.append(f"Unsupported hash algorithm: {hash_algo}")
            
            if 'sha1' in dkim_record.hash_algorithms and 'sha256' not in dkim_record.hash_algorithms:
                dkim_record.warnings.append("Using weak hash algorithm (sha1) without stronger alternative")
            
            # Record is valid if no errors
            dkim_record.valid = len(dkim_record.errors) == 0
            
            logger.debug(f"[{trace_id}] DKIM record parsed successfully, valid: {dkim_record.valid}")
            
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to parse DKIM record: {str(e)}")
            dkim_record.errors.append(f"Failed to parse DKIM record: {str(e)}")
            dkim_record.valid = False
        
        return dkim_record

    @trace_function("extract_key_length")
    def _extract_key_length(self, public_key: str, trace_id: str) -> int:
        """
        Extract key length from a base64 encoded public key
        
        Args:
            public_key: Base64 encoded public key
            trace_id: Trace ID for logging
            
        Returns:
            Key length in bits
        """
        if not public_key:
            return 0
            
        try:
            # Decode base64 key
            key_data = base64.b64decode(public_key)
            
            # Attempt to determine key length
            # This is a simplified approach - proper ASN.1 parsing would be better
            # But this works for most RSA keys
            
            # RSA public keys start with a specific sequence
            if len(key_data) > 50:  # Reasonable minimum length for an RSA key
                # Estimate the key length based on the length of the decoded key
                # RSA key length in bits is approximately (decoded_length - overhead) * 8 / 2
                # This is an approximation
                key_length = (len(key_data) - 20) * 4
                
                # Round to nearest standard key size
                if key_length > 3500:
                    return 4096
                elif key_length > 2700:
                    return 3072  
                elif key_length > 1500:
                    return 2048
                elif key_length > 768:
                    return 1024
                elif key_length > 384:
                    return 512
                else:
                    return 256
            else:
                return len(key_data) * 8  # Probably an Ed25519 key or similar
                
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to extract key length: {e}")
            return 0

    @trace_function("assess_security_level")
    def _assess_security_level(self, record: DKIMRecord, trace_id: str) -> str:
        """
        Assess the security level of a DKIM record
        
        Args:
            record: Parsed DKIM record
            trace_id: Trace ID for logging
            
        Returns:
            Security level: "high", "medium", "low", or "none"
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _assess_security_level: {trace_id}")
            trace_id = ensure_trace_id()
        
        if not record.valid:
            return "none"
        
        # Check for revoked keys
        if not record.public_key:
            return "none"
        
        # For testing mode, cap at medium
        if record.testing:
            return "medium"
        
        # Score based on key type and length
        if record.key_type == "ed25519":
            return "high"  # Ed25519 is always considered strong
        
        # RSA key length evaluation
        if record.key_length >= 2048:
            return "high"
        elif record.key_length >= 1024:
            return "medium"
        else:
            return "low"

    @trace_function("generate_recommendations")
    def _generate_recommendations(self, record: DKIMRecord, trace_id: str) -> List[str]:
        """
        Generate recommendations for DKIM improvement
        
        Args:
            record: Parsed DKIM record
            trace_id: Trace ID for logging
            
        Returns:
            List of recommendations
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _generate_recommendations: {trace_id}")
            trace_id = ensure_trace_id()
        
        recommendations = []
        
        # Check for revoked keys
        if not record.public_key:
            recommendations.append("Configure a valid DKIM public key")
            return recommendations
        
        # Check key type
        if record.key_type == "rsa":
            # RSA key length recommendations
            if record.key_length < 1024:
                recommendations.append("Increase RSA key length to at least 2048 bits (current key is critically weak)")
            elif record.key_length < 2048:
                recommendations.append("Increase RSA key length to at least 2048 bits (current key is becoming weak)")
            elif record.key_length < 3072:
                recommendations.append("Consider increasing RSA key length to 3072 or 4096 bits for future-proofing")
        
        # Hash algorithm recommendations
        if 'sha1' in record.hash_algorithms and len(record.hash_algorithms) == 1:
            recommendations.append("Add SHA-256 hash algorithm support (SHA-1 is weak)")
        elif 'sha1' in record.hash_algorithms:
            recommendations.append("Remove SHA-1 hash algorithm support (SHA-256 is sufficient)")
        elif 'sha256' not in record.hash_algorithms:
            recommendations.append("Add SHA-256 hash algorithm support")
        
        # Testing mode recommendations
        if record.testing:
            recommendations.append("Remove testing flag (t=y) once DKIM setup is verified")
        
        # Service type recommendations
        if '*' in record.service_types:
            recommendations.append("Consider restricting service types instead of using wildcard (*)")
            
        logger.debug(f"[{trace_id}] Generated {len(recommendations)} DKIM recommendations")
        return recommendations

    @trace_function("record_dkim_statistics")
    def _record_dkim_statistics(self, result: DKIMResult, trace_id: str):
        """
        Record DKIM validation statistics
        
        Args:
            result: DKIM validation result
            trace_id: Trace ID for logging
        """
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _record_dkim_statistics: {trace_id}")
            trace_id = ensure_trace_id()
        
        try:
            # Use the statistics module if available
            if self.dns_stats:
                self.dns_stats.record_dkim_statistics(
                    trace_id=trace_id,
                    domain=result.domain,
                    selector=result.selector,
                    has_dkim=result.has_dkim,
                    key_type=result.key_type,
                    key_length=result.key_length,
                    security_level=result.security_level,
                    dns_lookups=result.dns_lookups,
                    processing_time_ms=result.execution_time_ms,
                    errors='; '.join(result.errors) if result.errors else None
                )
                logger.debug(f"[{trace_id}] DKIM statistics recorded")
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to record DKIM statistics: {e}")


# Main DKIM check function for the validation engine
@trace_function("dkim_check")
def dkim_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    DKIM validation function for the Email Verification Engine
    
    Args:
        context: Dictionary containing:
            - email: Email address being validated
            - trace_id: Optional trace ID for logging
            - selector: Optional DKIM selector to check
            
    Returns:
        Dict with DKIM validation results
    """
    # Ensure context has valid trace_id
    context = ensure_context_has_trace_id(context)
    trace_id = context['trace_id']
    
    email = context.get("email", "")
    selector = context.get("dkim_selector", None)
    
    if not email or '@' not in email:
        logger.error(f"[{trace_id}] Invalid email format for DKIM check: {email}")
        return {
            "valid": False,
            "error": "Invalid email format for DKIM check",
            "has_dkim": False,
            "trace_id": trace_id
        }
    
    domain = email.split('@')[1].lower().strip()
    
    # Create child trace for DKIM validation
    child_trace_id = create_child_trace_id(trace_id)
    validator = DKIMValidator(child_trace_id)
    
    start_time = time.time()
    try:
        logger.info(f"[{trace_id}] Starting DKIM validation for domain: {domain}")
        
        dkim_result = validator.validate_dkim(domain, selector, child_trace_id)
        execution_time = (time.time() - start_time) * 1000
        
        # Create result dictionary instead of direct database update
        result_dict = {
            "selector": dkim_result.selector,
            "valid": dkim_result.has_dkim and len(dkim_result.errors) == 0,
            "has_dkim": dkim_result.has_dkim,
            "key_type": dkim_result.key_type,
            "key_length": dkim_result.key_length,
            "hash_algorithms": dkim_result.hash_algorithms,
            "service_types": dkim_result.service_types,
            "flags": dkim_result.flags,
            "found_selectors": dkim_result.found_selectors,
            "testing": dkim_result.testing,
            "security_level": dkim_result.security_level,
            "dns_lookups": dkim_result.dns_lookups,
            "execution_time_ms": execution_time,
            "domain": domain,
            "errors": dkim_result.errors,
            "warnings": dkim_result.warnings,
            "recommendations": dkim_result.recommendations,
            "trace_id": trace_id
        }
        
        # Store in server_policies format for consistency
        server_policies = context.get('server_policies', {})
        if isinstance(server_policies, str):
            try:
                server_policies = json.loads(server_policies)
            except:
                server_policies = {}
        elif not isinstance(server_policies, dict):
            server_policies = {}
            
        # Update with DKIM information
        server_policies['dkim'] = {
            'valid': dkim_result.has_dkim and len(dkim_result.errors) == 0,
            'has_dkim': dkim_result.has_dkim,
            'selector': dkim_result.selector,
            'found_selectors': dkim_result.found_selectors,
            'key_type': dkim_result.key_type, 
            'key_length': dkim_result.key_length,
            'security_level': dkim_result.security_level,
            'recommendations': dkim_result.recommendations
        }
        
        context['server_policies'] = server_policies
        context['dkim_result'] = result_dict
        
        logger.info(f"[{trace_id}] DKIM validation completed successfully for {domain}")
        try:
            dns_stats = DNSServerStats()
            dns_stats.record_dkim_statistics(
                trace_id=trace_id,
                domain=domain,
                selector=dkim_result.selector or '',
                has_dkim=dkim_result.has_dkim,
                key_type=dkim_result.key_type or '',
                key_length=dkim_result.key_length or 0,
                security_level=dkim_result.security_level or 'none',
                dns_lookups=dkim_result.dns_lookups,
                processing_time_ms=execution_time,
                errors='; '.join(dkim_result.errors) if dkim_result.errors else None
            )
            logger.debug(f"[{trace_id}] DKIM statistics recorded for {domain}")
            
            dns_stats.store_dkim_analysis(
                domain=domain,
                selector=dkim_result.selector or '',
                result=result_dict,
                trace_id=trace_id
            )
            logger.debug(f"[{trace_id}] DKIM analysis recorded for history: {domain}")
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to store DKIM analysis: {str(e)}", exc_info=True)
        return result_dict
        
    except Exception as e:
        execution_time = (time.time() - start_time) * 1000
        logger.error(f"[{trace_id}] DKIM validation error for {domain}: {str(e)}")
        return {
            "valid": False,
            "error": f"DKIM validation error: {str(e)}",
            "has_dkim": False,
            "domain": domain,
            "execution_time_ms": execution_time,
            "trace_id": trace_id
        }