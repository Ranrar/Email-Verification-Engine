"""
Email Validation Process Logic
===================================
Contains functions for processing validation results and calculating confidence scores
"""

from typing import Dict, Any, Optional
from src.managers.log import get_logger
from src.helpers.dbh import sync_db
from src.engine.result import EmailValidationResult, MxInfrastructure

logger = get_logger()

def process_validation_results(result: EmailValidationResult, validation_results: Dict[str, Any]) -> None:
    """Process validation results and update the EmailValidationResult object"""
    logger.debug(f"[{result.trace_id}] Processing validation results: {validation_results.keys()}")
    
    # Black/White list check processing
    if 'black_white_check' in validation_results:
        bw_check = validation_results.get('black_white_check', {})
        if bw_check.get('blacklisted', False):
            # Domain is blacklisted, set error and stop validation
            result.error_message = f"Domain is blacklisted: {bw_check.get('error', 'Unknown reason')}"
            result.is_valid = False
            result.blacklist_info = {
                'blacklisted': True,
                'source': bw_check.get('source', 'Unknown'),
                'whitelisted': False
            }
            return
        elif bw_check.get('whitelisted', False):
            # Domain is whitelisted, log this information
            result.blacklist_info = {
                'blacklisted': False,
                'whitelisted': True,
                'source': bw_check.get('source', 'Unknown')
            }
            logger.info(f"[{result.trace_id}] Domain is whitelisted by {bw_check.get('source')}")
        else:
            # Domain is neither blacklisted nor whitelisted
            result.blacklist_info = {
                'blacklisted': False,
                'whitelisted': False
            }
    
    # Domain check processing
    if 'domain_check' in validation_results:
        domain_check = validation_results.get('domain_check', {})
        # Handle the nested domain_check structure from validate_domain
        domain_info = domain_check.get('domain_check', domain_check)
        
        if not domain_info.get('domain_exists', True):
            # Domain doesn't exist, set error message
            result.error_message = domain_check.get('error', 'Domain does not exist')
            # Set validation status
            result.is_valid = False
            # Skip other validations as domain doesn't exist
            result.mx_records = []
            return
        
        # If domain exists, continue with normal processing
        if domain_info.get('has_mx_records'):
            result.mx_records = domain_info.get('mx_records', [])
    
    # Format check processing - look for both possible key names
    format_result = None
    if 'email_format_results' in validation_results:
        format_result = validation_results.get('email_format_results', {})
    elif 'email_format_resaults' in validation_results:  # Note the typo in 'resaults'
        format_result = validation_results.get('email_format_resaults', {})
    
    if format_result:
        result.is_format_valid = format_result.get('valid', False)
        logger.info(f"[{result.trace_id}] Format check result: {result.is_format_valid}")
    elif validation_results.get('valid') is not None:
        result.is_format_valid = validation_results.get('valid', False)
    else:
        result.is_format_valid = False
    
    # Enhanced MX records processing
    mx_check = validation_results.get('mx_records') or validation_results.get('check_mx_records', {})
    
    if isinstance(mx_check, dict):
        # Extract basic MX data (for backward compatibility)
        if 'records' in mx_check and mx_check['records']:
            result.mx_records = mx_check['records']
        elif 'mx_records' in mx_check:
            result.mx_records = mx_check['mx_records']
            
        if 'preferences' in mx_check:
            result.mx_preferences = mx_check['preferences']
        elif 'mx_preferences' in mx_check:
            result.mx_preferences = mx_check['mx_preferences']
            
        # Legacy MX IP field
        if 'mx_record' in mx_check:
            result.mx_ip = mx_check['mx_record']
        
        # Extract enhanced MX infrastructure data
        if 'mx_infrastructure' in mx_check:
            result.mx_infrastructure = mx_check['mx_infrastructure']
            
        # Extract IP address data
        if 'ip_addresses' in mx_check:
            result.mx_ip_addresses = mx_check['ip_addresses']
            # Also update the legacy mx_ip field for backward compatibility
            ipv4_list = mx_check['ip_addresses'].get('ipv4', [])
            if ipv4_list and not result.mx_ip:
                result.mx_ip = ipv4_list[0] if isinstance(ipv4_list, list) else str(ipv4_list)
        
        # Extract infrastructure info
        if 'infrastructure_info' in mx_check:
            result.infrastructure_info = mx_check['infrastructure_info']
            
        # Extract email provider info
        if 'email_provider' in mx_check:
            provider_data = mx_check['email_provider']
            # Only keep the fields we need
            result.email_provider = {
                "provider_name": provider_data.get('provider_name', "Unknown"),
                "self_hosted": provider_data.get('self_hosted', False),
                "provider_detected": provider_data.get('provider_name', "Unknown") != "Unknown"
            }
        
        # Log successful MX validation with enhanced data
        if mx_check.get('valid', False):
            logger.debug(f"[{result.trace_id}] MX records found: {len(result.mx_records)} records")
            if result.email_provider and result.email_provider.get('provider_detected'):
                logger.debug(f"[{result.trace_id}] Email provider: {result.email_provider.get('provider_name')}")
    
    # SPF check processing
    if 'spf_check' in validation_results:
        spf_data = validation_results.get('spf_check', {})
        
        # Update basic SPF status
        result.spf_status = spf_data.get('spf_result', '')
        
        # Add error message logging here
        if spf_data.get("error"):
            logger.error(f"[{result.trace_id}] SPF permerror: {spf_data['error']}")
        
        # Store detailed SPF information
        result.spf_details = {
            'valid': spf_data.get('valid', False),
            'record': spf_data.get('spf_record', ''),
            'reason': spf_data.get('spf_reason', ''),
            'mechanism_matched': spf_data.get('spf_mechanism_matched', ''),
            'dns_lookups': spf_data.get('spf_dns_lookups', 0),
            'explanation': spf_data.get('spf_explanation', ''),
            'domain': spf_data.get('spf_domain', ''),
            'execution_time': spf_data.get('execution_time', 0)
        }
        
        # Log SPF validation result
        logger.info(f"[{result.trace_id}] SPF validation result: {result.spf_status}")
        if result.spf_status == 'pass':
            logger.debug(f"[{result.trace_id}] SPF passed via mechanism: {spf_data.get('spf_mechanism_matched', 'unknown')}")
        elif result.spf_status == 'softfail':
            # Log softfails as debug instead of warning
            logger.debug(f"[{result.trace_id}] SPF {result.spf_status}: {spf_data.get('spf_reason', '')}")
        elif result.spf_status == 'fail':
            # SPF fail is a normal result, not a warning - log as info
            error_msg = spf_data.get('spf_reason', '') or spf_data.get('error', '')
            logger.info(f"[{result.trace_id}] SPF {result.spf_status}: {error_msg}")
        elif result.spf_status == 'permerror':
            # Only permerror should be logged as warning (actual configuration issues)
            error_msg = spf_data.get('spf_reason', '') or spf_data.get('error', '')
            logger.warning(f"[{result.trace_id}] SPF {result.spf_status}: {error_msg}")
        elif result.spf_status in ['temperror', 'none']:
            # Log these as debug - they're informational
            error_msg = spf_data.get('spf_reason', '') or spf_data.get('error', '')
            logger.debug(f"[{result.trace_id}] SPF {result.spf_status}: {error_msg}")
    
    # DMARC check processing
    if 'dmarc_check' in validation_results:
        dmarc_data = validation_results.get('dmarc_check', {})
        
        # Update basic DMARC status
        result.dmarc_status = dmarc_data.get('policy', '')
        
        # Store detailed DMARC information
        result.dmarc_details = {
            'valid': dmarc_data.get('valid', False),
            'has_dmarc': dmarc_data.get('has_dmarc', False),
            'policy': dmarc_data.get('policy', 'none'),
            'policy_strength': dmarc_data.get('policy_strength', 'none'),
            'alignment_mode': dmarc_data.get('alignment_mode', ''),
            'percentage_covered': dmarc_data.get('percentage_covered', 0),
            'aggregate_reporting': dmarc_data.get('aggregate_reporting', False),
            'forensic_reporting': dmarc_data.get('forensic_reporting', False),
            'organizational_domain': dmarc_data.get('organizational_domain', ''),
            'recommendations': dmarc_data.get('recommendations', []),
            'record': dmarc_data.get('record_details', {}).get('raw_record', ''),
            'execution_time': dmarc_data.get('execution_time', 0)
        }
        
        # Log DMARC validation result
        logger.info(f"[{result.trace_id}] DMARC validation result: {result.dmarc_status}")
        if result.dmarc_details['has_dmarc']:
            logger.debug(f"[{result.trace_id}] DMARC policy: {result.dmarc_details['policy']}, "
                        f"strength: {result.dmarc_details['policy_strength']}")
            
            # Log reporting configuration
            if result.dmarc_details['aggregate_reporting'] or result.dmarc_details['forensic_reporting']:
                logger.debug(f"[{result.trace_id}] DMARC reporting: "
                            f"aggregate={str(result.dmarc_details['aggregate_reporting']).lower()}, "
                            f"forensic={str(result.dmarc_details['forensic_reporting']).lower()}")
        else:
            logger.debug(f"[{result.trace_id}] No DMARC record found for domain {result.domain}")
    
    # DKIM check processing
    if 'dkim_check' in validation_results:
        dkim_data = validation_results.get('dkim_check', {})
        
        # Update basic DKIM status
        result.dkim_status = dkim_data.get('security_level', '')
        
        # Add error message logging here
        if dkim_data.get("error"):
            logger.error(f"[{result.trace_id}] DKIM error: {dkim_data['error']}")
        
        # Store detailed DKIM information
        result.dkim_details = {
            'valid': dkim_data.get('valid', False),
            'has_dkim': dkim_data.get('has_dkim', False),
            'selector': dkim_data.get('selector', ''),
            'found_selectors': dkim_data.get('found_selectors', []),
            'key_type': dkim_data.get('key_type', ''),
            'key_length': dkim_data.get('key_length', 0),
            'security_level': dkim_data.get('security_level', 'none'),
            'hash_algorithms': dkim_data.get('hash_algorithms', []),
            'recommendations': dkim_data.get('recommendations', []),
            'testing': dkim_data.get('testing', False),
            'execution_time': dkim_data.get('execution_time_ms', 0)
        }
        
        # Log DKIM validation result
        logger.info(f"[{result.trace_id}] DKIM validation result: {result.dkim_status}")
        if result.dkim_details['has_dkim']:
            logger.debug(f"[{result.trace_id}] DKIM key: {result.dkim_details['key_type']} "
                        f"{result.dkim_details['key_length']} bits, "
                        f"security: {result.dkim_details['security_level']}")
            
            # Log recommendations if available
            if result.dkim_details['recommendations']:
                logger.debug(f"[{result.trace_id}] DKIM recommendations: "
                            f"{', '.join(result.dkim_details['recommendations'])}")
        else:
            logger.debug(f"[{result.trace_id}] No valid DKIM records found for domain {result.domain}")
    
    # Legacy DNS security processing
    if 'dns_security' in validation_results:
        dns_sec = validation_results.get('dns_security', {})
        # Only update spf_status if not already set by detailed SPF check
        if not result.spf_status:
            result.spf_status = dns_sec.get('spf', "")
        result.dkim_status = dns_sec.get('dkim', "")
        result.dmarc_status = dns_sec.get('dmarc', "")
    
    # SMTP check processing
    if 'smtp_validation' in validation_results:
        smtp_result = validation_results.get('smtp_validation', {})
        
        # Make sure the banner is explicitly assigned to the result object
        result.smtp_banner = smtp_result.get('smtp_banner', '')
        result.smtp_result = smtp_result.get('smtp_result', False)
        result.smtp_vrfy = smtp_result.get('smtp_vrfy', False)
        result.smtp_supports_tls = smtp_result.get('smtp_supports_tls', False)
        result.smtp_supports_auth = smtp_result.get('smtp_supports_auth', False)
        result.smtp_flow_success = smtp_result.get('smtp_flow_success', False)
        result.smtp_error_code = smtp_result.get('smtp_error_code')
        result.smtp_server_message = smtp_result.get('smtp_server_message', '')
        
        # Additional fields
        result.connection_success = smtp_result.get('connection_success', False)
    
    # IMAP validation check processing
    if 'imap_validation' in validation_results:
        imap_data = validation_results.get('imap_validation', {})
        
        # Update basic IMAP status
        result.imap_status = "available" if imap_data.get("has_imap", False) else "unavailable"
        if imap_data.get("error"):
            result.imap_status = "error"
            
        # Store detailed IMAP information
        result.imap_details = {
            'has_imap': imap_data.get('has_imap', False),
            'servers_found': len(imap_data.get('imap_servers', [])),
            'security_level': imap_data.get('security_level', 'none'),
            'supports_ssl': imap_data.get('supports_ssl', False),
            'supports_starttls': imap_data.get('supports_starttls', False),
            'supports_oauth': imap_data.get('supports_oauth', False),
            'servers': imap_data.get('imap_servers', []),
            'recommendations': imap_data.get('recommendations', []),
            'error': imap_data.get('error', ''),
            'execution_time_ms': imap_data.get('duration_ms', 0)
        }        
        # Log IMAP validation result
        if result.imap_status == "available":
            logger.info(f"[{result.trace_id}] IMAP available for {result.domain}: " 
                       f"security={imap_data.get('security_level', 'none')}, "
                       f"servers={len(imap_data.get('imap_servers', []))}")
        else:
            logger.info(f"[{result.trace_id}] IMAP {result.imap_status} for {result.domain}")
            
        # Log detailed information at debug level
        if result.imap_status == "available":
            logger.debug(f"[{result.trace_id}] IMAP details: SSL={imap_data.get('supports_ssl', False)}, "
                        f"STARTTLS={imap_data.get('supports_starttls', False)}, "
                        f"OAuth={imap_data.get('supports_oauth', False)}")
    
    if 'disposable_check' in validation_results:
        disposable_check = validation_results.get('disposable_check', {})
        result.is_disposable = disposable_check.get('is_disposable', False)
    
    if 'catch_all_check' in validation_results:
        catch_all = validation_results.get('catch_all_check', {})
        result.catch_all = catch_all.get('is_catch_all', False)
    
    # Calculate overall validity and confidence score
    calculate_validity_and_confidence(result, validation_results)

def calculate_validity_and_confidence(result: EmailValidationResult, validation_results: Dict[str, Any]) -> None:
    """Calculate overall validity and confidence score using database-driven scoring rules"""
    # Check if domain is blacklisted - immediate failure
    if result.blacklist_info and result.blacklist_info.get('blacklisted', False):
        result.is_valid = False
        result.confidence_score = 0
        result.confidence_level = "Blacklisted"
        return

    # Check if MX fallback was used
    used_fallback = False
    if isinstance(result.mx_infrastructure, MxInfrastructure):
        used_fallback = result.mx_infrastructure.used_fallback
    elif isinstance(result.mx_infrastructure, dict):
        used_fallback = result.mx_infrastructure.get('used_fallback', False)

    # UPDATED VALIDITY LOGIC - Now includes SMTP validation result
    result.is_valid = (
        result.is_format_valid and  # Must have valid format
        bool(result.mx_records) and # Must have MX records
        not used_fallback and       # Must not be using fallback A records
        result.smtp_result          # Must have successful SMTP validation
    )

    # Log the validation factors for debugging
    logger.debug(f"[{result.trace_id}] Validity factors: format={result.is_format_valid}, " +
                f"mx_records={bool(result.mx_records)}, not_fallback={not used_fallback}, " +
                f"smtp_result={result.smtp_result}")

    # --- Begin dynamic scoring ---
    db = sync_db
    # Fetch all scoring rules
    scoring_rows = db.fetch("SELECT check_name, score_value, is_penalty FROM validation_scoring")
    scoring = {row['check_name']: row for row in scoring_rows} if scoring_rows else {}

    # Update checks based on result object to include IMAP
    checks = {
        'valid_format': result.is_format_valid,
        'not_disposable': not result.is_disposable,
        'disposable': result.is_disposable,
        'blacklisted': result.blacklist_info.get('blacklisted', False) if result.blacklist_info else False,
        'mx_records': bool(result.mx_records) and not used_fallback,
        'spf_found': bool(result.spf_status),
        'dkim_found': bool(result.dkim_status),
        'smtp_connection': result.smtp_result,
        'catch_all': result.catch_all is True,
        'no_catch_all': result.catch_all is False,
        'vrfy_confirmed': (result.smtp_banner != '') or result.smtp_flow_success,
        'imap_available': result.imap_status == "available",
        'pop3_available': result.pop3_status == "available",
        'dmarc_found': bool(result.dmarc_status) and result.dmarc_details.get('has_dmarc', False),
        'dmarc_strong_policy': result.dmarc_details.get('policy_strength', '') in ['strong', 'moderate'],
    }
    
    score = 0
    max_score = 0

    for check_name, rule in scoring.items():
        value = checks.get(check_name, False)
        if value and not rule['is_penalty']:
            score += rule['score_value']
        if not value and rule['is_penalty']:
            # Penalty applies only if the negative condition is met
            score -= rule['score_value']
        if not rule['is_penalty']:
            max_score += rule['score_value']

    # Clamp score to [0, max_score]
    score = max(0, min(score, max_score)) if max_score > 0 else 0