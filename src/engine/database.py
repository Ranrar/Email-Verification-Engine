"""
Email Validation Database Operations
===================================
Contains functions for database operations related to email validation
"""

import json
import dataclasses
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from src.managers.log import Axe
from src.helpers.dbh import sync_db
from src.engine.result import (
    EmailValidationResult, 
    MxInfrastructure,
    IpAddresses, 
    InfrastructureInfo,
    sanitize_value
)

logger = Axe()

def to_int_or_none(value: Any) -> Optional[int]:
    """
    Convert a value to an integer or return None if the conversion fails.
    
    Args:
        value: The value to convert to an integer
        
    Returns:
        int if conversion succeeds, None otherwise
    """
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

def log_to_database(result: EmailValidationResult) -> Optional[int]:
    """Log validation result to database with full schema and sanitization."""
    try:
        db = sync_db
        data = result.to_dict()

        # Extract and organize database fields
        db_fields = _prepare_db_fields(data, result.trace_id)
        
        # Insert the main validation record
        record_id = _insert_validation_record(db, db_fields)
        
        # Store related MX infrastructure data if available
        if record_id and result.mx_records and result.trace_id:
            _store_mx_infrastructure(db, record_id, result.mx_infrastructure, result.mx_ip_addresses, 
                                    result.infrastructure_info, result.trace_id, 
                                    result.domain, result.email_provider, result.mx_ip)
            logger.debug(f"[{result.trace_id}] MX infrastructure data stored for {result.email}")
        
        # Log detailed information about what was stored
        mx_count = len(result.mx_records) if result.mx_records else 0
        if result.mx_ip_addresses is not None:
            if isinstance(result.mx_ip_addresses, IpAddresses):
                ipv4_count = len(result.mx_ip_addresses.ipv4)
                ipv6_count = len(result.mx_ip_addresses.ipv6)
            else:
                ipv4_count = len(result.mx_ip_addresses.get('ipv4', []))
                ipv6_count = len(result.mx_ip_addresses.get('ipv6', []))
        else:
            ipv4_count = 0
            ipv6_count = 0
        logger.info(f"[{result.trace_id}] Database record created for {result.email}: "
                   f"ID={record_id}, MX={mx_count}, IPv4={ipv4_count}, IPv6={ipv6_count}")
        
        return record_id

    except Exception as e:
        logger.error(f"[{result.trace_id}] Failed to log validation result for {result.email}: {e}", exc_info=True)
        return None

def _prepare_db_fields(data: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
    """Prepare fields for database insertion with proper sanitization."""
    import json

    mx_infrastructure_dict = data.get('mx_infrastructure', {})
    email_provider_dict = data.get('email_provider', {})
    blacklist_info = data.get("blacklist_info", {})
    domain_info = data.get("domain_check", {})
    infrastructure_info = data.get("infrastructure_info", {})
    spf_details = data.get("spf_details", {})
    dmarc_details = data.get("dmarc_details", {})
    
    # Make sure it includes full SPF details from the validation
    if isinstance(spf_details, dict) and data.get("spf_result"):
        # Ensure we have a full set of SPF details
        spf_details.update({
            "spf_result": data.get("spf_result", ""),
            "spf_record": data.get("spf_record", ""),
            "spf_mechanism_matched": data.get("spf_mechanism_matched", ""),
            "spf_dns_lookups": data.get("spf_dns_lookups", 0),
            "spf_reason": data.get("spf_reason", ""),
            "errors": data.get("errors", []),
            "warnings": data.get("warnings", []),
            "dns_lookup_log": data.get("dns_lookup_log", [])
        })
    
    # Make sure it includes full DMARC details from the validation
    if isinstance(dmarc_details, dict) and data.get("dmarc_status"):
        # Ensure we have a full set of DMARC details
        dmarc_details.update({
            "policy": data.get("dmarc_status", "none"),
            "has_dmarc": data.get("has_dmarc", False),
            "policy_strength": data.get("policy_strength", "none"),
            "alignment_mode": data.get("alignment_mode", ""),
            "percentage_covered": data.get("percentage_covered", 0),
            "aggregate_reporting": data.get("aggregate_reporting", False),
            "forensic_reporting": data.get("forensic_reporting", False),
            "organizational_domain": data.get("organizational_domain", ""),
            "recommendations": data.get("recommendations", [])
        })
    
    return {
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc),
        "email": sanitize_value(data.get("email")),
        "domain": sanitize_value(data.get("domain")),

        # SMTP fields - access directly from data instead of nested smtp_details
        "smtp_result": str(data.get("smtp_result", False)),
        "smtp_banner": sanitize_value(data.get("smtp_banner", "")),
        "smtp_vrfy": str(data.get("smtp_vrfy", False)),
        "smtp_supports_tls": data.get("smtp_supports_tls", False),
        "smtp_supports_auth": data.get("smtp_supports_auth", False),
        "smtp_flow_success": data.get("smtp_flow_success", False),
        "smtp_error_code": to_int_or_none(data.get("smtp_error_code")),
        "smtp_server_message": sanitize_value(data.get("smtp_server_message", "")),
        
        # Capture timeout information in existing fields
        "port": sanitize_value(data.get("port", "")),

        # Make sure main error_message field captures SMTP errors
        "error_message": data.get("error_message") or (
            f"SMTP error: {data.get('smtp_server_message')}" 
            if data.get('smtp_server_message') else ""
        ),

        # MX fields
        "mx_records": sanitize_value(data.get("mx_records")),
        "mx_ip": sanitize_value(data.get("mx_ip")),
        "mx_preferences": sanitize_value(data.get("mx_preferences")),
        "mx_analysis": json.dumps(mx_infrastructure_dict) if mx_infrastructure_dict else None,

        # Email provider
        "email_provider_id": _get_provider_id(sync_db, email_provider_dict) if email_provider_dict else None,
        "email_provider_info": json.dumps(email_provider_dict) if email_provider_dict else None,

        # Reverse DNS and WHOIS
        "reverse_dns": sanitize_value(infrastructure_info.get("ptr_records")),
        "whois_info": sanitize_value(infrastructure_info.get("whois_data")),

        # Black/White list info
        "blacklist_info": json.dumps(blacklist_info) if blacklist_info else None,

        # Domain check
        "catch_all": str(data.get("catch_all", "")) if data.get("catch_all", None) is not None else "",
        "disposable": str(data.get("is_disposable", "")),

        # IMAP/POP3 (if available)
        "imap_status": str(data.get("imap_status", "")),
        "imap_info": json.dumps(data.get("imap_info", {})) if data.get("imap_info") else None,
        "imap_security": str(data.get("imap_security", "")),
        "pop3_status": str(data.get("pop3_status", "")),
        "pop3_info": json.dumps(data.get("pop3_info", {})) if data.get("pop3_info") else None,
        "pop3_security": str(data.get("pop3_security", "")),

        # SPF/DKIM/DMARC/server policies
        "spf_status": data.get("spf_status", ""),
        "spf_details": json.dumps(spf_details) if spf_details else None,
        "dkim_status": data.get("dkim_status", ""),
        "dmarc_status": data.get("dmarc_status", ""),
        "server_policies": json.dumps(data.get("server_policies", {})) if data.get("server_policies") else None,

        # Validation status and scoring
        "is_valid": data.get("is_valid", False),
        "confidence_score": to_int_or_none(data.get("confidence_score", 0)),
        "execution_time": data.get("execution_time", 0.0),
        "timing_details": json.dumps(data.get("timings", {})) if data.get("timings") else None,
        "check_count": to_int_or_none(data.get("check_count", 1)),
        "batch_id": to_int_or_none(data.get("batch_id")),
        "raw_result": json.dumps(data) if data else None,
        "validation_complete": data.get("validation_complete", True),
    }

def _get_provider_id(db, email_provider_dict):
    """Get or create email provider ID."""
    try:
        provider_name = email_provider_dict.get('provider_name') if email_provider_dict else None
        if provider_name and provider_name != "Unknown":
            provider_result = db.fetchrow(
                "SELECT id FROM email_providers WHERE name = $1",
                provider_name
            )
            
            if provider_result:
                return provider_result['id']
        return None
    except Exception as e:
        logger.warning(f"Failed to get provider ID: {e}")
        return None

def _get_provider_name(db, email_provider_dict):
    """Get provider name from email_provider info."""
    try:
        provider_name = email_provider_dict.get('provider_name') if email_provider_dict else None
        return provider_name if provider_name and provider_name != "Unknown" else None
    except Exception as e:
        logger.warning(f"Failed to get provider name: {e}")
        return None

def _insert_validation_record(db, values: Dict[str, Any]) -> Optional[int]:
    """Insert or upsert the main validation record and return its ID."""
    columns = [
        "trace_id", "timestamp", "email", "domain",
        "smtp_result", "smtp_banner", "smtp_vrfy", "smtp_supports_tls", "smtp_supports_auth",
        "smtp_flow_success", "smtp_error_code", "smtp_server_message", "port",
        "mx_records", "mx_ip", "mx_preferences", "mx_analysis",
        "email_provider_id", "email_provider_info", "reverse_dns", "whois_info",
        "catch_all", "imap_status", "imap_info", "imap_security",
        "pop3_status", "pop3_info", "pop3_security",
        "spf_status", "spf_details", "dkim_status", "dmarc_status", "server_policies",
        "disposable", "blacklist_info", "error_message",
        "is_valid", "confidence_score", "execution_time", "timing_details",
        "check_count", "batch_id", "raw_result", "validation_complete"
    ]
    # Prepare the values in the correct order
    insert_values = [values.get(col) for col in columns]
    col_str = ", ".join(columns)
    placeholders = ", ".join([f"${i+1}" for i in range(len(columns))])

    # Build the ON CONFLICT update string (skip id and trace_id)
    update_cols = [col for col in columns if col not in ("id", "trace_id")]
    update_str = ",\n                ".join([f"{col} = EXCLUDED.{col}" for col in update_cols])

    sql = f"""
        INSERT INTO email_validation_records (
            {col_str}
        ) VALUES (
            {placeholders}
        )
        ON CONFLICT (trace_id) 
        DO UPDATE SET 
            {update_str}
        RETURNING id
    """

    result = db.fetchrow(sql, *insert_values)
    return result['id'] if result else None

def _store_mx_infrastructure(db, record_id: int, mx_infrastructure, mx_ip_addresses,
                         infrastructure_info, trace_id: str, domain: str, 
                         email_provider_dict: Dict, mx_ip: str) -> None:
    """Store MX infrastructure data in dedicated tables."""
    try:
        # Store MX infrastructure data
        if isinstance(mx_infrastructure, MxInfrastructure) or mx_infrastructure:
            # Extract infrastructure data
            mx_data = mx_infrastructure
            primary_mx = mx_data.primary if isinstance(mx_data, MxInfrastructure) else mx_data.get('primary', {})
            has_failover = mx_data.has_failover if isinstance(mx_data, MxInfrastructure) else mx_data.get('has_failover', False)
            load_balanced = mx_data.load_balanced if isinstance(mx_data, MxInfrastructure) else mx_data.get('load_balanced', False)
            used_fallback = mx_data.used_fallback if isinstance(mx_data, MxInfrastructure) else mx_data.get('used_fallback', False)
            
            # Get provider information
            provider_name = _get_provider_name(db, email_provider_dict)
            
            # Insert MX infrastructure record
            mx_infra_id = _insert_mx_infrastructure(db, record_id, primary_mx, 
                                                  has_failover, load_balanced, 
                                                  provider_name, used_fallback, 
                                                  trace_id, domain, mx_ip)
            
            # Store IP addresses
            if mx_infra_id:
                _store_ip_addresses(db, mx_infra_id, mx_ip_addresses, infrastructure_info, trace_id)
    except Exception as e:
        logger.warning(f"Failed to store MX infrastructure: {e}")

def _insert_mx_infrastructure(db, record_id: int, primary_mx: Dict, 
                        has_failover: bool, load_balanced: bool,
                        provider_name: Optional[str], is_fallback: bool,
                        trace_id: str, domain: str, mx_ip: str) -> Optional[int]:
    """Insert MX infrastructure record and return its ID."""
    try:
        import json
        
        mx_infra_values = {
            "trace_id": trace_id,
            "email_validation_id": record_id,
            "domain": domain,
            "mx_record": mx_ip or (primary_mx.get('servers', [])[0] if primary_mx.get('servers') else ""),
            "is_primary": True,
            "preference": primary_mx.get('preference'),
            "has_failover": has_failover,
            "load_balanced": load_balanced,
            "provider_name": provider_name,
            "is_self_hosted": False,  # Default value
            "is_fallback": is_fallback,
            "ip_addresses": None,  # Will be filled in _store_ip_addresses
            "ptr_records": None,  # Will be filled in _store_ip_addresses
            "geo_info": None,  # Will be filled in _store_ip_addresses
            "whois_summary": None,  # Will be filled in _store_ip_addresses
        }
        
        mx_columns = ", ".join(mx_infra_values.keys())
        mx_placeholders = ", ".join([f"${i+1}" for i in range(len(mx_infra_values))])
        
        mx_infra_result = db.fetchrow(
            f"INSERT INTO mx_infrastructure ({mx_columns}) VALUES ({mx_placeholders}) RETURNING id",
            *mx_infra_values.values()
        )
        
        return mx_infra_result['id'] if mx_infra_result else None
    except Exception as e:
        logger.warning(f"Failed to insert MX infrastructure: {e}")
        return None
        
def _store_ip_addresses(db, mx_infra_id: int, mx_ip_addresses, infrastructure_info, trace_id: str) -> None:
    """Store MX infrastructure data in dedicated tables."""
    _store_ipv4_addresses(db, mx_infra_id, mx_ip_addresses, infrastructure_info, trace_id)
    _store_ipv6_addresses(db, mx_infra_id, mx_ip_addresses, trace_id)

def _store_ipv4_addresses(db, mx_infra_id: int, mx_ip_addresses, infrastructure_info, trace_id: str) -> None:
    """Store IPv4 address records."""
    ipv4_list = mx_ip_addresses.ipv4 if isinstance(mx_ip_addresses, IpAddresses) else mx_ip_addresses.get('ipv4', [])
    for ip in ipv4_list:
        try:
            if not ip:
                continue
                
            # Get geo data if available
            geo_data = (mx_ip_addresses.geo if isinstance(mx_ip_addresses, IpAddresses) else mx_ip_addresses.get('geo', {})).get(ip, {})
            
            # Get PTR record if available
            ptr_records = infrastructure_info.ptr_records if isinstance(infrastructure_info, InfrastructureInfo) else infrastructure_info.get('ptr_records', [])
            ptr_record = next((r['ptr'] for r in ptr_records if r['ip'] == ip), None)
            
            ip_values = {
                "trace_id": trace_id,
                "mx_infrastructure_id": mx_infra_id,
                "ip_address": ip,
                "ip_version": 4,
                "is_private": False,
                "ptr_record": ptr_record,
                "country_code": geo_data.get('country') if geo_data else None,
                "region": geo_data.get('region') if geo_data else None,
                "provider": geo_data.get('provider') if geo_data else None
            }
            
            ip_columns = ", ".join(ip_values.keys())
            ip_placeholders = ", ".join([f"${i+1}" for i in range(len(ip_values))])
            
            db.execute(
                f"INSERT INTO mx_ip_addresses ({ip_columns}) VALUES ({ip_placeholders})",
                *ip_values.values()
            )
        except Exception as e:
            logger.warning(f"Failed to store IPv4 address {ip}: {e}")

def _store_ipv6_addresses(db, mx_infra_id: int, mx_ip_addresses, trace_id: str) -> None:
    """Store IPv6 address records."""
    ipv6_list = mx_ip_addresses.ipv6 if isinstance(mx_ip_addresses, IpAddresses) else mx_ip_addresses.get('ipv6', [])
    for ip in ipv6_list:
        try:
            if not ip:
                continue
                
            # Get geo data if available
            geo_data = (mx_ip_addresses.geo if isinstance(mx_ip_addresses, IpAddresses) else mx_ip_addresses.get('geo', {})).get(ip, {})
            
            ip_values = {
                "trace_id": trace_id,
                "mx_infrastructure_id": mx_infra_id,
                "ip_address": ip,
                "ip_version": 6,
                "is_private": False,
                "ptr_record": None,
                "country_code": geo_data.get('country') if geo_data else None,
                "region": geo_data.get('region') if geo_data else None,
                "provider": geo_data.get('provider') if geo_data else None
            }
            
            ip_columns = ", ".join(ip_values.keys())
            ip_placeholders = ", ".join([f"${i+1}" for i in range(len(ip_values))])
            
            db.execute(
                f"INSERT INTO mx_ip_addresses ({ip_columns}) VALUES ({ip_placeholders})",
                *ip_values.values()
            )
        except Exception as e:
            logger.warning(f"Failed to store IPv6 address {ip}: {e}")

def log_validation_operation(trace_id: str, operation: str, category: Optional[str] = None, 
                           status: str = "info", duration_ms: Optional[float] = None, 
                           details: Optional[Dict[str, Any]] = None) -> bool:
    """
    Log a validation operation to the validation_logs table.
    
    Args:
        trace_id: The trace ID of the validation
        operation: Name of the operation being performed
        category: Category of the operation (e.g., 'smtp', 'dns', 'format')
        status: Status of the operation (e.g., 'success', 'failure', 'info')
        duration_ms: Duration of the operation in milliseconds
        details: Additional details as a dictionary
        
    Returns:
        bool: Whether logging was successful
    """
    try:
        db = sync_db
        
        values = {
            "trace_id": trace_id,
            "timestamp": datetime.now(timezone.utc),
            "operation": operation,
            "category": category,
            "status": status,
            "duration_ms": duration_ms,
            "details": json.dumps(details) if details else None
        }
        
        columns = ", ".join(values.keys())
        placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
        
        db.execute(
            f"INSERT INTO validation_logs ({columns}) VALUES ({placeholders})",
            *values.values()
        )
        
        return True
    except Exception as e:
        logger.error(f"Failed to log validation operation: {e}", exc_info=True)
        return False

def log_batch_info(batch_id, name=None, source=None, status="processing", settings=None, 
                 total_emails=0, processed_emails=0, success_count=0, failed_count=0, 
                 error_message=None, completed=False) -> Optional[int]:
    """Log batch operation information to database."""
    try:
        db = sync_db
        
        # Prepare values
        now = datetime.now(timezone.utc)
        values = {
            "created_at": now,
            "batch_id": batch_id,
            "name": name or f"Batch {batch_id[:8]}",
            "source": source or "API",
            "completed_at": now if completed else None,
            "total_emails": total_emails,
            "processed_emails": processed_emails,
            "success_count": success_count,
            "failed_count": failed_count,
            "status": status,
            "error_message": error_message or "",
            "settings_snapshot": settings or {}
        }
        
        columns = ", ".join(values.keys())
        placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
        
        # Use UPSERT pattern for updating existing batch records
        sql = f"""
            INSERT INTO batch_info (
                {columns}
            ) VALUES (
                {placeholders}
            )
            ON CONFLICT (batch_id) 
            DO UPDATE SET 
                name = EXCLUDED.name,
                completed_at = EXCLUDED.completed_at,
                total_emails = EXCLUDED.total_emails,
                processed_emails = EXCLUDED.processed_emails,
                success_count = EXCLUDED.success_count,
                failed_count = EXCLUDED.failed_count,
                status = EXCLUDED.status,
                error_message = EXCLUDED.error_message
            RETURNING id
        """
        
        result = db.fetchrow(sql, *values.values())
        batch_record_id = result['id'] if result else None
        
        logger.info(f"Logged batch info for {batch_id} to database with ID {batch_record_id}")
        return batch_record_id
        
    except Exception as e:
        logger.error(f"Failed to log batch info for {batch_id}: {e}", exc_info=True)
        return None
