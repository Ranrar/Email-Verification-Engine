"""
Email Verification Engine - Domain Validation Module
==================================================
Early domain verification to ensure the domain exists before other validation steps.
"""

from typing import Dict, Any
from src.engine.functions.mx import fetch_mx_records
from src.managers.log import get_logger

logger = get_logger()

def validate_domain(context):
    """
    Validate domain existence early in the validation process
    
    Args:
        context: The validation context containing email and trace_id
        
    Returns:
        Dict with validation results focusing on domain existence
    """
    # Extract email and domain
    email = context.get("email", "")
    domain = email.split('@')[1] if '@' in email else ""
    trace_id = context.get("trace_id", "")
    
    if not domain:
        logger.info(f"[{trace_id}] Invalid format, missing domain part")
        return {
            "valid": False,
            "is_deliverable": False,
            "email": email,
            "domain": "",
            "error": "Invalid email format",
            "error_code": "INVALID_FORMAT",
            "confidence_score": 0,
            "domain_check": {
                "valid": False,
                "domain_exists": False,
                "has_mx_records": False,
                "error": "Invalid format"
            }
        }
    
    # Log the domain check
    logger.debug(f"[{trace_id}] Checking if domain {domain} exists")
    
    # Get MX records to verify domain existence
    mx_result = fetch_mx_records(context)
    
    # Check for non-existent domain
    if not mx_result.get("valid") and mx_result.get("error") == "Domain does not exist":
        logger.info(f"[{trace_id}] Domain {domain} does not exist")
        return {
            "valid": False,
            "is_deliverable": False,
            "email": email,
            "domain": domain,
            "error": "Domain does not exist",
            "error_code": "DOMAIN_NOT_FOUND",
            "confidence_score": 0,
            "execution_time": mx_result.get("execution_time", 0),
            "domain_check": {
                "valid": False,
                "domain_exists": False,
                "has_mx_records": False,
                "error": "Domain does not exist"
            }
        }
    
    # Domain exists, continue validation
    return {
        "valid": True,
        "domain": domain,
        "domain_check": {
            "valid": mx_result.get("valid", False),
            "domain_exists": True,
            "has_mx_records": bool(mx_result.get("records")),
            "mx_records": mx_result.get("records", []),
            "execution_time": mx_result.get("execution_time", 0)
        }
    }