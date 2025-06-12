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
from src.managers.log import Axe
from src.managers.time import now_utc, EnhancedOperationTimer
from src.engine.functions.statistics import DNSServerStats
from src.helpers.dbh import sync_db

# Initialize logging
logger = Axe()

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

class DMARCValidator:
    """DMARC record validator implementing RFC 7489"""
    
    def __init__(self):
        """Initialize with required managers"""
        self.dns_manager = DNSManager()
        self.rate_limit_manager = RateLimitManager()
        
        # Add domain info extractor for organizational domain detection
        try:
            from src.engine.functions.whois import DomainInfoExtractor
            self.domain_info = DomainInfoExtractor()
        except ImportError:
            self.domain_info = None
            logger.debug("DomainInfoExtractor not available, using fallback domain detection")
        
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
            logger.debug("DMARC cache TTL not configured in rate limits, using default of 3600 seconds")
            self.dmarc_cache_ttl = 3600
        except Exception as e:
            logger.warning(f"Failed to get DMARC cache TTL from rate limits: {e}, using default")
            self.dmarc_cache_ttl = 3600
        
        # Get DNS timeout from DNS manager
        try:
            # Use the DNS manager's own timeout method which has proper fallback
            self.dns_timeout = self.dns_manager.get_timeout()
            logger.debug(f"Using DNS timeout from DNS manager: {self.dns_timeout}s")
        except Exception as e:
            logger.warning(f"Failed to get DNS timeout from DNS manager: {e}, using default")
            self.dns_timeout = 5.0
        
        logger.debug(f"DMARC Validator initialized - Cache TTL: {self.dmarc_cache_ttl}s, "
                    f"DNS Timeout: {self.dns_timeout}s, "
                    f"Stats Available: {self.dns_stats is not None}")

    def validate_dmarc(self, domain: str, trace_id: Optional[str] = None) -> DMARCResult:
        """Validate DMARC record for a domain with enhanced timing and statistics"""
        
        with EnhancedOperationTimer(f"DMARC validation for {domain}", trace_id) as timer:
            # Don't generate new trace_id if one is provided
            if trace_id is None:
                # Only generate if absolutely no trace_id is provided (shouldn't happen in normal operation)
                trace_id = f"dmarc_fallback_{int(time.time() * 1000)}"
                logger.warning(f"No trace_id provided for DMARC validation of {domain}, using fallback: {trace_id}")
        
            logger.info(f"[{trace_id}] Starting DMARC validation for domain {domain}")
            
            result = DMARCResult(domain=domain)
            
            # Validate domain format
            if not self._is_valid_domain(domain):
                result.errors.append(f"Invalid domain format: {domain}")
                result.execution_time_ms = timer.elapsed_ms or 0.0
                return result
            
            # Get organizational domain for DMARC lookup
            org_domain = self._get_organizational_domain(domain)
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
                result.alignment_mode = self._get_alignment_mode(dmarc_record)
                
                # Assess policy strength
                result.policy_strength = self._assess_policy_strength(dmarc_record)
                
                # Generate recommendations
                result.recommendations = self._generate_recommendations(dmarc_record)
                
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

    def _get_dmarc_record(self, domain: str, trace_id: Optional[str] = None) -> Tuple[Optional[DMARCRecord], int]:
        """Get DMARC record from DNS with proper cache integration"""
        dmarc_hostname = f"_dmarc.{domain}"
        
        # Use centralized cache key system - FIXED
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
            dmarc_record = self._parse_dmarc_record(dmarc_txt)
            
            # Cache result with proper TTL
            cache_manager.set(cache_key, dmarc_record, ttl=self.dmarc_cache_ttl)
            
            return dmarc_record, 1
            
        except Exception as e:
            logger.debug(f"[{trace_id}] DMARC lookup failed for {dmarc_hostname}: {str(e)}")
            cache_manager.set(cache_key, None, ttl=300)
            return None, 1

    def _parse_dmarc_record(self, record: str) -> DMARCRecord:
        """Parse a DMARC TXT record"""
        dmarc_record = DMARCRecord(raw_record=record)
        
        try:
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
                dmarc_record.rua_addresses = self._parse_report_addresses(tags['rua'])
            
            if 'ruf' in tags:
                dmarc_record.ruf_addresses = self._parse_report_addresses(tags['ruf'])
            
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
            
        except Exception as e:
            dmarc_record.errors.append(f"Failed to parse DMARC record: {str(e)}")
            dmarc_record.valid = False
        
        return dmarc_record

    def _parse_report_addresses(self, addresses_str: str) -> List[str]:
        """Parse and validate DMARC reporting addresses"""
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
                logger.debug(f"Invalid DMARC report address format: {email}")
        
        return addresses

    def _get_organizational_domain(self, domain: str) -> str:
        """Get organizational domain for DMARC lookup using domain info extractor"""
        try:
            # Use domain info extractor if available
            if self.domain_info and hasattr(self.domain_info, 'extract_organizational_domain'):
                return self.domain_info.extract_organizational_domain(domain)
        
            # Simple fallback if domain info extractor is not available
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
        
        except Exception as e:
            logger.warning(f"Error determining organizational domain for {domain}: {e}")
            return domain

    def _get_alignment_mode(self, record: DMARCRecord) -> str:
        """Determine the strictest alignment mode"""
        if record.alignment_spf == 's' or record.alignment_dkim == 's':
            return "strict"
        return "relaxed"

    def _assess_policy_strength(self, record: DMARCRecord) -> str:
        """Assess the strength of DMARC policy with enhanced scoring"""
        if not record.valid:
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
            return "strong"
        elif score >= 60:
            return "moderate"
        elif score >= 30:
            return "weak"
        else:
            return "none"

    def _generate_recommendations(self, record: DMARCRecord) -> List[str]:
        """Generate recommendations for DMARC improvement"""
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
        
        return recommendations

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if not domain or len(domain) > 255:
            return False
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))

    def _record_dmarc_statistics(self, result: DMARCResult, trace_id: str):
        """Record DMARC validation statistics"""
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

    def _store_dmarc_analysis(self, domain: str, result: DMARCResult, trace_id: str):
        """Store DMARC analysis results for reporting and analytics"""
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

    def _validate_dmarc_syntax(self, record: str) -> List[str]:
        """Additional DMARC syntax validation"""
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
        
        return errors

# Main DMARC check function for the validation engine
def dmarc_check(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    DMARC validation function for the Email Verification Engine
    """
    email = context.get("email", "")
    trace_id = context.get("trace_id", "")
    
    if not email or '@' not in email:
        return {
            "valid": False,
            "error": "Invalid email format for DMARC check",
            "has_dmarc": False,
            "policy": "none",
            "policy_strength": "none",
            "execution_time": 0
        }
    
    domain = email.split('@')[-1].lower().strip()
    validator = DMARCValidator()
    
    start_time = time.time()
    try:
        # Ensure trace_id is not empty
        if not trace_id:
            logger.warning(f"Empty trace_id provided for DMARC validation of {domain}")
            trace_id = f"dmarc_missing_{int(time.time() * 1000)}"
        
        dmarc_result = validator.validate_dmarc(domain, trace_id)  # Pass the correct trace_id
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
                "timestamp": now_utc().isoformat()
            }
        }
        
        return result
        
    except Exception as e:
        execution_time = (time.time() - start_time) * 1000
        logger.error(f"[{trace_id}] DMARC validation error: {str(e)}")
        return {
            "valid": False,
            "error": f"DMARC validation error: {str(e)}",
            "has_dmarc": False,
            "policy": "none",
            "policy_strength": "none",
            "domain": domain,
            "execution_time": execution_time
        }