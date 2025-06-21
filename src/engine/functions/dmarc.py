"""
Email Verification Engine - DMARC (Domain-based Message Authentication, 
Reporting & Conformance) Validation
====================================================================
Implements RFC 7489 compliant DMARC record validation.

DMARC Check Process:
1. Query DNS for DMARC policy records
2. Parse DMARC policy syntax and tags
3. Validate policy configuration
4. Assess policy strength and coverage
5. Return DMARC policy status and recommendations

Note: This validates DMARC DNS policy records, not message authentication
(as we don't have actual email messages to verify against SPF/DKIM).
"""

import time
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
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
class DMARCRecord:
    """Represents a parsed DMARC record"""
    version: str = ""
    policy: str = ""
    subdomain_policy: str = ""
    alignment_spf: str = "r"  # relaxed by default
    alignment_dkim: str = "r"  # relaxed by default
    percentage: int = 100
    rua_addresses: List[str] = field(default_factory=list)  # Aggregate reports
    ruf_addresses: List[str] = field(default_factory=list)  # Forensic reports
    failure_options: str = ""
    report_format: str = "afrf"
    report_interval: int = 86400  # Daily by default
    raw_record: str = ""
    valid: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class DMARCResult:
    """DMARC validation result"""
    domain: str = ""
    has_dmarc: bool = False
    policy: str = "none"
    subdomain_policy: str = ""
    policy_strength: str = "none"  # none, weak, moderate, strong
    alignment_mode: str = "relaxed"
    percentage_covered: int = 0
    aggregate_reporting: bool = False
    forensic_reporting: bool = False
    record: Optional[DMARCRecord] = None
    organizational_domain: str = ""
    dns_lookups: int = 0
    execution_time_ms: float = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    trace_id: Optional[str] = None  # Add trace_id to result

class DMARCValidator:
    """DMARC record validator implementing RFC 7489"""
    
    @trace_function("dmarc_validator_init")
    def __init__(self, trace_id: Optional[str] = None):
        """Initialize with required managers"""
        # Ensure we have a valid trace_id
        self.trace_id = ensure_trace_id(trace_id)
        
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        
        # Add domain info extractor for organizational domain detection
        try:
            from src.engine.functions.whois import DomainInfoExtractor
            self.domain_info = DomainInfoExtractor()
        except ImportError:
            self.domain_info = None
            logger.debug(f"[{self.trace_id}] DomainInfoExtractor not available, using fallback domain detection")
        
        # Initialize DNS stats if available
        if DNSServerStats:
            self.dns_stats = DNSServerStats()
        else:
            self.dns_stats = None

        # Get DMARC-specific cache TTL from rate limit manager
        try:
            self.dmarc_cache_ttl = self.rate_limit_manager.get_dmarc_cache_ttl()
            
            if not isinstance(self.dmarc_cache_ttl, (int, float)) or self.dmarc_cache_ttl <= 0:
                self.dmarc_cache_ttl = 3600  # Default 1 hour
        except KeyError:
            logger.debug(f"[{self.trace_id}] DMARC cache TTL not configured in rate limits, using default of 3600 seconds")
            self.dmarc_cache_ttl = 3600
        except Exception as e:
            logger.warning(f"[{self.trace_id}] Failed to get DMARC cache TTL from rate limits: {e}, using default")
            self.dmarc_cache_ttl = 3600
        
        # Get DNS timeout from DNS manager
        try:
            # Use the DNS manager's own timeout method which has proper fallback
            self.dns_timeout = self.dns_manager.get_timeout()
            logger.debug(f"[{self.trace_id}] Using DNS timeout from DNS manager: {self.dns_timeout}s")
        except Exception as e:
            logger.warning(f"[{self.trace_id}] Failed to get DNS timeout from DNS manager: {e}, using default")
            self.dns_timeout = 5.0
        
        logger.debug(f"[{self.trace_id}] DMARC Validator initialized - Cache TTL: {self.dmarc_cache_ttl}s, "
                    f"DNS Timeout: {self.dns_timeout}s, "
                    f"Stats Available: {self.dns_stats is not None}")

    @trace_function("validate_dmarc")
    def validate_dmarc(self, domain: str, trace_id: Optional[str] = None) -> DMARCResult:
        """Validate DMARC record for a domain with enhanced timing and statistics"""
        
        # Ensure we have a valid trace_id
        trace_id = ensure_trace_id(trace_id)
        
        # Validate trace_id at entry point
        if not validate_trace_id(trace_id):
            logger.error(f"Invalid trace_id received in validate_dmarc: {trace_id}")
            trace_id = ensure_trace_id()
        
        with EnhancedOperationTimer(f"DMARC validation for {domain}", trace_id) as timer:
            logger.info(f"[{trace_id}] Starting DMARC validation for domain {domain}")
            
            result = DMARCResult(domain=domain, trace_id=trace_id)
            
            # Validate domain format
            if not self._is_valid_domain(domain, trace_id):
                result.errors.append(f"Invalid domain format: {domain}")
                result.execution_time_ms = timer.elapsed_ms or 0.0
                return result
            
            # Get organizational domain for DMARC lookup
            org_domain = self._get_organizational_domain(domain, trace_id)
            result.organizational_domain = org_domain
            
            # Look up DMARC record
            dmarc_record, dns_lookups = self._get_dmarc_record(org_domain, trace_id)
            result.dns_lookups = dns_lookups
            
            if dmarc_record:
                result.has_dmarc = True
                result.record = dmarc_record
                result.policy = dmarc_record.policy
                result.subdomain_policy = dmarc_record.subdomain_policy or dmarc_record.policy
                result.percentage_covered = dmarc_record.percentage
                result.aggregate_reporting = len(dmarc_record.rua_addresses) > 0
                result.forensic_reporting = len(dmarc_record.ruf_addresses) > 0
                
                # Determine alignment mode
                result.alignment_mode = self._get_alignment_mode(dmarc_record, trace_id)
                
                # Assess policy strength
                result.policy_strength = self._assess_policy_strength(dmarc_record, trace_id)
                
                # Generate recommendations
                result.recommendations = self._generate_recommendations(dmarc_record, trace_id)
                
                # Collect errors and warnings from record
                result.errors.extend(dmarc_record.errors)
                result.warnings.extend(dmarc_record.warnings)
            else:
                result.warnings.append(f"No DMARC record found for {org_domain}")
                result.recommendations.append("Consider implementing DMARC policy for email security")
            
            result.execution_time_ms = timer.elapsed_ms or 0.0
            
            # Record statistics
            self._record_dmarc_statistics(result, trace_id)
            
            # Optionally store analysis results
            self._store_dmarc_analysis(domain, result, trace_id)
            
            logger.info(f"[{trace_id}] DMARC validation completed for {domain}: "
                       f"policy={result.policy}, strength={result.policy_strength}")
            
            return result

    @trace_function("get_dmarc_record")
    def _get_dmarc_record(self, domain: str, trace_id: str) -> Tuple[Optional[DMARCRecord], int]:
        """Get DMARC record from DNS with proper cache integration"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _get_dmarc_record: {trace_id}")
            trace_id = ensure_trace_id()
        
        dmarc_hostname = f"_dmarc.{domain}"
        
        # Use centralized cache key system
        cache_key = CacheKeys.dmarc(dmarc_hostname)
        
        cached_result = cache_manager.get(cache_key)
        if cached_result is not None:
            logger.debug(f"[{trace_id}] Cache hit for DMARC record {dmarc_hostname}")
            return cached_result, 0
        
        try:
            logger.debug(f"[{trace_id}] Querying DMARC record for {dmarc_hostname}")
            
            # Query TXT records
            txt_records = self.dns_manager.resolve(dmarc_hostname, 'TXT')
            
            if not txt_records:
                cache_manager.set(cache_key, None, ttl=300)
                return None, 1
            
            # Find DMARC record (should start with v=DMARC1)
            dmarc_txt = None
            for record in txt_records:
                record_str = str(record).strip('"')
                if record_str.startswith('v=DMARC1'):
                    dmarc_txt = record_str
                    break
            
            if not dmarc_txt:
                cache_manager.set(cache_key, None, ttl=300)
                return None, 1
            
            # Parse DMARC record
            dmarc_record = self._parse_dmarc_record(dmarc_txt, trace_id)
            
            # Cache result with proper TTL
            cache_manager.set(cache_key, dmarc_record, ttl=self.dmarc_cache_ttl)
            
            return dmarc_record, 1
            
        except Exception as e:
            logger.debug(f"[{trace_id}] DMARC lookup failed for {dmarc_hostname}: {str(e)}")
            cache_manager.set(cache_key, None, ttl=300)
            return None, 1

    @trace_function("parse_dmarc_record")
    def _parse_dmarc_record(self, record: str, trace_id: str) -> DMARCRecord:
        """Parse a DMARC TXT record"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _parse_dmarc_record: {trace_id}")
            trace_id = ensure_trace_id()
        
        dmarc_record = DMARCRecord(raw_record=record)
        
        try:
            logger.debug(f"[{trace_id}] Parsing DMARC record: {record}")
            
            # Parse key-value pairs
            tags = {}
            for part in record.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    tags[key.strip()] = value.strip()
            
            # Extract and validate each tag
            dmarc_record.version = tags.get('v', '')
            dmarc_record.policy = tags.get('p', '')
            dmarc_record.subdomain_policy = tags.get('sp', '')
            dmarc_record.alignment_spf = tags.get('aspf', 'r')
            dmarc_record.alignment_dkim = tags.get('adkim', 'r')
            dmarc_record.failure_options = tags.get('fo', '0')
            dmarc_record.report_format = tags.get('rf', 'afrf')
            
            # Parse percentage
            try:
                dmarc_record.percentage = int(tags.get('pct', '100'))
                if not 0 <= dmarc_record.percentage <= 100:
                    dmarc_record.errors.append(f"Invalid percentage: {dmarc_record.percentage}")
            except ValueError:
                dmarc_record.errors.append(f"Invalid percentage format: {tags.get('pct')}")
            
            # Parse report interval
            try:
                dmarc_record.report_interval = int(tags.get('ri', '86400'))
            except ValueError:
                dmarc_record.warnings.append(f"Invalid report interval: {tags.get('ri')}")
            
            # Parse reporting addresses
            if 'rua' in tags:
                dmarc_record.rua_addresses = self._parse_report_addresses(tags['rua'], trace_id)
            
            if 'ruf' in tags:
                dmarc_record.ruf_addresses = self._parse_report_addresses(tags['ruf'], trace_id)
            
            # Validate version
            if dmarc_record.version != 'DMARC1':
                dmarc_record.errors.append(f"Invalid DMARC version: {dmarc_record.version}")
            
            # Validate policy
            if dmarc_record.policy not in ['none', 'quarantine', 'reject']:
                dmarc_record.errors.append(f"Invalid policy: {dmarc_record.policy}")
            
            # Validate subdomain policy
            if dmarc_record.subdomain_policy and dmarc_record.subdomain_policy not in ['none', 'quarantine', 'reject']:
                dmarc_record.errors.append(f"Invalid subdomain policy: {dmarc_record.subdomain_policy}")
            
            # Validate alignment modes
            if dmarc_record.alignment_spf not in ['r', 's']:
                dmarc_record.errors.append(f"Invalid SPF alignment: {dmarc_record.alignment_spf}")
            
            if dmarc_record.alignment_dkim not in ['r', 's']:
                dmarc_record.errors.append(f"Invalid DKIM alignment: {dmarc_record.alignment_dkim}")
            
            # Record is valid if no errors
            dmarc_record.valid = len(dmarc_record.errors) == 0
            
            logger.debug(f"[{trace_id}] DMARC record parsed successfully, valid: {dmarc_record.valid}")
            
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to parse DMARC record: {str(e)}")
            dmarc_record.errors.append(f"Failed to parse DMARC record: {str(e)}")
            dmarc_record.valid = False
        
        return dmarc_record

    @trace_function("parse_report_addresses")
    def _parse_report_addresses(self, addresses_str: str, trace_id: str) -> List[str]:
        """Parse and validate DMARC reporting addresses"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _parse_report_addresses: {trace_id}")
            trace_id = ensure_trace_id()
        
        addresses = []
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        for addr in addresses_str.split(','):
            addr = addr.strip()
            
            # Handle URI format (rua/ruf can have size limits)
            if addr.startswith('mailto:'):
                email = addr[7:]
                # Check for size parameter: mailto:admin@example.com!50m
                if '!' in email:
                    email = email.split('!')[0]
            else:
                email = addr
            
            # Validate email format
            if email and email_pattern.match(email):
                addresses.append(email)
            elif email:  # Log invalid addresses for debugging
                logger.debug(f"[{trace_id}] Invalid DMARC report address format: {email}")
        
        return addresses

    @trace_function("get_organizational_domain")
    def _get_organizational_domain(self, domain: str, trace_id: str) -> str:
        """Get organizational domain for DMARC lookup using domain info extractor"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _get_organizational_domain: {trace_id}")
            trace_id = ensure_trace_id()
        
        try:
            # Use domain info extractor if available
            if self.domain_info and hasattr(self.domain_info, 'extract_organizational_domain'):
                org_domain = self.domain_info.extract_organizational_domain(domain)
                logger.debug(f"[{trace_id}] Organizational domain for {domain}: {org_domain}")
                return org_domain
        
            # Simple fallback if domain info extractor is not available
            parts = domain.split('.')
            if len(parts) >= 2:
                org_domain = '.'.join(parts[-2:])
                logger.debug(f"[{trace_id}] Fallback organizational domain for {domain}: {org_domain}")
                return org_domain
            
            logger.debug(f"[{trace_id}] Using domain as-is for organizational domain: {domain}")
            return domain
        
        except Exception as e:
            logger.warning(f"[{trace_id}] Error determining organizational domain for {domain}: {e}")
            return domain

    @trace_function("get_alignment_mode")
    def _get_alignment_mode(self, record: DMARCRecord, trace_id: str) -> str:
        """Determine the strictest alignment mode"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _get_alignment_mode: {trace_id}")
            trace_id = ensure_trace_id()
        
        if record.alignment_spf == 's' or record.alignment_dkim == 's':
            alignment = "strict"
        else:
            alignment = "relaxed"
        
        logger.debug(f"[{trace_id}] DMARC alignment mode: {alignment}")
        return alignment

    @trace_function("assess_policy_strength")
    def _assess_policy_strength(self, record: DMARCRecord, trace_id: str) -> str:
        """Assess the strength of DMARC policy with enhanced scoring"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _assess_policy_strength: {trace_id}")
            trace_id = ensure_trace_id()
        
        if not record.valid:
            logger.debug(f"[{trace_id}] DMARC record invalid, strength: none")
            return "none"
        
        score = 0
        
        # Base policy scoring (0-30 points)
        policy_scores = {'reject': 30, 'quarantine': 20, 'none': 5}
        score += policy_scores.get(record.policy, 0)
        
        # Percentage coverage (0-25 points)
        score += (record.percentage / 100) * 25
        
        # Alignment mode (0-20 points)
        if record.alignment_spf == 's':
            score += 10
        if record.alignment_dkim == 's':
            score += 10
        
        # Reporting setup (0-15 points)
        if record.rua_addresses:
            score += 10
        if record.ruf_addresses:
            score += 5
        
        # Subdomain policy (0-10 points)
        if record.subdomain_policy:
            subdomain_scores = {'reject': 10, 'quarantine': 7, 'none': 3}
            score += subdomain_scores.get(record.subdomain_policy, 0)
        
        # Determine strength based on total score (0-100)
        if score >= 80:
            strength = "strong"
        elif score >= 60:
            strength = "moderate"
        elif score >= 30:
            strength = "weak"
        else:
            strength = "none"
        
        logger.debug(f"[{trace_id}] DMARC policy strength assessment: {strength} (score: {score})")
        return strength

    @trace_function("generate_recommendations")
    def _generate_recommendations(self, record: DMARCRecord, trace_id: str) -> List[str]:
        """Generate recommendations for DMARC improvement"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _generate_recommendations: {trace_id}")
            trace_id = ensure_trace_id()
        
        recommendations = []
        
        if record.policy == 'none':
            recommendations.append("Consider upgrading from 'none' to 'quarantine' policy after monitoring")
        
        if record.policy == 'quarantine':
            recommendations.append("Consider upgrading to 'reject' policy for maximum protection")
        
        if record.percentage < 100:
            recommendations.append(f"Consider increasing policy coverage from {record.percentage}% to 100%")
        
        if not record.rua_addresses:
            recommendations.append("Add aggregate reporting (rua) to monitor DMARC performance")
        
        if record.alignment_spf == 'r' and record.alignment_dkim == 'r':
            recommendations.append("Consider strict alignment mode for enhanced security")
        
        if not record.subdomain_policy:
            recommendations.append("Consider adding explicit subdomain policy (sp)")
        
        logger.debug(f"[{trace_id}] Generated {len(recommendations)} DMARC recommendations")
        return recommendations

    @trace_function("is_valid_domain")
    def _is_valid_domain(self, domain: str, trace_id: str) -> bool:
        """Validate domain format"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _is_valid_domain: {trace_id}")
            trace_id = ensure_trace_id()
        
        if not domain or len(domain) > 255:
            logger.debug(f"[{trace_id}] Domain validation failed: empty or too long")
            return False
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        is_valid = bool(domain_pattern.match(domain))
        logger.debug(f"[{trace_id}] Domain {domain} validation: {is_valid}")
        return is_valid

    @trace_function("record_dmarc_statistics")
    def _record_dmarc_statistics(self, result: DMARCResult, trace_id: str):
        """Record DMARC validation statistics"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _record_dmarc_statistics: {trace_id}")
            trace_id = ensure_trace_id()
        
        try:
            # Use the statistics module instead of direct database insertion
            if self.dns_stats and hasattr(self.dns_stats, 'record_dmarc_statistics'):
                self.dns_stats.record_dmarc_statistics(
                    trace_id=trace_id,
                    domain=result.domain,
                    result=result.policy,
                    policy_strength=result.policy_strength,
                    dns_lookups=result.dns_lookups,
                    processing_time_ms=result.execution_time_ms,
                    raw_record=result.record.raw_record if result.record else None,
                    has_reporting=result.aggregate_reporting or result.forensic_reporting,
                    alignment_mode=result.alignment_mode,
                    error_message='; '.join(result.errors) if result.errors else None
                )
                logger.debug(f"[{trace_id}] DMARC statistics recorded via statistics module")
            else:
                logger.warning(f"[{trace_id}] DNS stats module not available for DMARC statistics recording")
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to record DMARC statistics: {e}")

    @trace_function("store_dmarc_analysis")
    def _store_dmarc_analysis(self, domain: str, result: DMARCResult, trace_id: str):
        """Store DMARC analysis results for reporting and analytics"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _store_dmarc_analysis: {trace_id}")
            trace_id = ensure_trace_id()
        
        try:
            # Use the statistics module for storing DMARC analysis
            if self.dns_stats and hasattr(self.dns_stats, 'store_dmarc_analysis'):
                # Convert DMARCResult to dict for the statistics module
                result_dict = {
                    'policy': result.policy,
                    'policy_strength': result.policy_strength,
                    'alignment_mode': result.alignment_mode,
                    'percentage_covered': result.percentage_covered,
                    'aggregate_reporting': result.aggregate_reporting,
                    'forensic_reporting': result.forensic_reporting,
                    'dns_lookups': result.dns_lookups,
                    'execution_time_ms': result.execution_time_ms,
                    'errors': result.errors,
                    'warnings': result.warnings,
                    'recommendations': result.recommendations
                }
                
                self.dns_stats.store_dmarc_analysis(domain, result_dict, trace_id)
                logger.debug(f"[{trace_id}] DMARC analysis stored via statistics module")
            else:
                logger.debug(f"[{trace_id}] Statistics module not available for DMARC analysis storage")
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to store DMARC analysis: {e}")

    @trace_function("validate_dmarc_syntax")
    def _validate_dmarc_syntax(self, record: str, trace_id: str) -> List[str]:
        """Additional DMARC syntax validation"""
        # Validate trace_id
        if not validate_trace_id(trace_id):
            logger.warning(f"Invalid trace_id in _validate_dmarc_syntax: {trace_id}")
            trace_id = ensure_trace_id()
        
        errors = []
        
        # Check for duplicate tags
        tags = []
        for part in record.split(';'):
            if '=' in part:
                tag = part.split('=')[0].strip()
                if tag in tags:
                    errors.append(f"Duplicate tag found: {tag}")
                tags.append(tag)
        
        # Check for unknown tags
        known_tags = ['v', 'p', 'sp', 'adkim', 'aspf', 'pct', 'fo', 'rf', 'ri', 'rua', 'ruf']
        for tag in tags:
            if tag not in known_tags:
                errors.append(f"Unknown DMARC tag: {tag}")
        
        # Policy must be present
        if 'p' not in tags:
            errors.append("Missing required policy tag (p)")
        
        logger.debug(f"[{trace_id}] DMARC syntax validation found {len(errors)} errors")
        return errors

# Main DMARC check function for the validation engine
@trace_function("dmarc_check")
def dmarc_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    DMARC validation function for the Email Verification Engine
    """
    # Ensure context has valid trace_id
    context = ensure_context_has_trace_id(context)
    trace_id = context['trace_id']
    
    email = context.get("email", "")
    
    if not email or '@' not in email:
        logger.error(f"[{trace_id}] Invalid email format for DMARC check: {email}")
        return {
            "valid": False,
            "error": "Invalid email format for DMARC check",
            "has_dmarc": False,
            "policy": "none",
            "policy_strength": "none",
            "execution_time": 0,
            "trace_id": trace_id
        }
    
    domain = email.split('@')[-1].lower().strip()
    
    # Create child trace for spawned operation
    child_trace_id = create_child_trace_id(trace_id)
    validator = DMARCValidator(child_trace_id)
    
    start_time = time.time()
    try:
        logger.debug(f"[{trace_id}] Starting DMARC validation for domain: {domain}")
        
        dmarc_result = validator.validate_dmarc(domain, child_trace_id)
        execution_time = (time.time() - start_time) * 1000
        
        # Create result dictionary instead of direct database update
        result_dict = {
            "policy": dmarc_result.policy,
            "policy_strength": dmarc_result.policy_strength,
            "has_dmarc": dmarc_result.has_dmarc,
            "alignment_mode": dmarc_result.alignment_mode,
            "percentage_covered": dmarc_result.percentage_covered,
            "aggregate_reporting": dmarc_result.aggregate_reporting,
            "forensic_reporting": dmarc_result.forensic_reporting,
            "organizational_domain": dmarc_result.organizational_domain,
            "subdomain_policy": dmarc_result.subdomain_policy,
            "dns_lookups": dmarc_result.dns_lookups,
            "recommendations": dmarc_result.recommendations,
            "execution_time_ms": execution_time,
            "trace_id": trace_id,
            "domain": domain,
            "errors": dmarc_result.errors if dmarc_result.errors else [],
            "warnings": dmarc_result.warnings if dmarc_result.warnings else [],
            "raw_record": dmarc_result.record.raw_record if dmarc_result.record else None
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
            
        # Update with DMARC information
        server_policies['dmarc'] = {
            'policy': dmarc_result.policy,
            'has_dmarc': dmarc_result.has_dmarc,
            'policy_strength': dmarc_result.policy_strength,
            'alignment_mode': dmarc_result.alignment_mode,
            'percentage_covered': dmarc_result.percentage_covered,
            'aggregate_reporting': dmarc_result.aggregate_reporting,
            'forensic_reporting': dmarc_result.forensic_reporting,
            'organizational_domain': dmarc_result.organizational_domain,
            'recommendations': dmarc_result.recommendations
        }
        
        context['server_policies'] = server_policies
        context['dmarc_result'] = result_dict  # Store result in context for access by other functions
        
        # Return comprehensive result
        result = {
            "valid": dmarc_result.has_dmarc,
            "has_dmarc": dmarc_result.has_dmarc,
            "policy": dmarc_result.policy,
            "subdomain_policy": dmarc_result.subdomain_policy,
            "policy_strength": dmarc_result.policy_strength,
            "alignment_mode": dmarc_result.alignment_mode,
            "percentage_covered": dmarc_result.percentage_covered,
            "aggregate_reporting": dmarc_result.aggregate_reporting,
            "forensic_reporting": dmarc_result.forensic_reporting,
            "organizational_domain": dmarc_result.organizational_domain,
            "dns_lookups": dmarc_result.dns_lookups,
            "execution_time": execution_time,
            "errors": dmarc_result.errors,
            "warnings": dmarc_result.warnings,
            "recommendations": dmarc_result.recommendations,
            "domain": domain,
            "trace_id": trace_id,
            
            # Additional metadata for comprehensive reporting
            "record_details": {
                "raw_record": dmarc_result.record.raw_record if dmarc_result.record else None,
                "version": dmarc_result.record.version if dmarc_result.record else None,
                "rua_count": len(dmarc_result.record.rua_addresses) if dmarc_result.record else 0,
                "ruf_count": len(dmarc_result.record.ruf_addresses) if dmarc_result.record else 0,
                "failure_options": dmarc_result.record.failure_options if dmarc_result.record else None
            },
            "analysis_metadata": {
                "validator_version": "1.0.0",
                "rfc_compliance": "RFC-7489",
                "cache_hit": dmarc_result.dns_lookups == 0,
                "timestamp": now_utc().isoformat(),
                "child_trace_id": child_trace_id
            }
        }
        
        logger.info(f"[{trace_id}] DMARC validation completed successfully for {domain}")
        return result
        
    except Exception as e:
        execution_time = (time.time() - start_time) * 1000
        logger.error(f"[{trace_id}] DMARC validation error for {domain}: {str(e)}")
        return {
            "valid": False,
            "error": f"DMARC validation error: {str(e)}",
            "has_dmarc": False,
            "policy": "none",
            "policy_strength": "none",
            "domain": domain,
            "execution_time": execution_time,
            "trace_id": trace_id
        }