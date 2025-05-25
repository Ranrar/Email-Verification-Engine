"""
Email Verification Engine
===================================
    Creae a new Email Format Check

# Example: Create a configuration with custom Gmail pattern
create_new_email_filter_regex_patterns(
    name="Gmail Validator", 
    regex_patterns={
        "basic": "^.+@.+\\..+$",
        "rfc5322": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)",
        "gmail_specific": "^[a-z0-9]+(\\.[a-z0-9]+)*@gmail\\.com$",
        "local_too_long": "^.{64,}@",
        "empty_parts": "^@|@$|@\\.|\\.$",
        "whitespace": "\\s+",
        "consecutive_dots": "\\.{2,}"
    },
    main_settings={"strict_mode": True, "basic_format_pattern": "gmail_specific"}
)    

"""

import json
from typing import Dict, Any, Optional
from src.managers.log import Axe

logger = Axe()

def create_new_email_filter_regex_patterns(
    name: str,
    regex_patterns: Dict[str, str],
    main_settings: Optional[Dict[str, Any]] = None,
    validation_steps: Optional[Dict[str, bool]] = None,
    pattern_checks: Optional[Dict[str, bool]] = None,
    format_options: Optional[Dict[str, bool]] = None,
    local_part_options: Optional[Dict[str, Any]] = None,
    domain_options: Optional[Dict[str, Any]] = None,
    idna_options: Optional[Dict[str, bool]] = None
) -> bool:
    """
    Create a new email filter regex pattern configuration and save it to the database.
    
    Args:
        name: Name for this configuration
        regex_patterns: Dictionary of regex patterns to use
        main_settings: Main configuration settings
        validation_steps: Which validation steps to enable/disable
        pattern_checks: Which pattern checks to enable/disable
        format_options: Options for basic format validation
        local_part_options: Options for local part validation
        domain_options: Options for domain validation
        idna_options: Options for IDNA handling
        
    Returns:
        bool: True if the configuration was saved successfully
    """
    from src.helpers.dbh import sync_db
    
    # Populate default values if not provided
    if main_settings is None:
        main_settings = {
            "strict_mode": False,
            "max_local_length": 64,
            "max_domain_length": 255,
            "max_total_length": 320,
            "basic_format_pattern": "basic"
        }
    
    if validation_steps is None:
        validation_steps = {
            "basic_format": True,
            "normalization": True,
            "length_limits": True,
            "local_part": True,
            "domain": True,
            "idna": True
        }
    
    if pattern_checks is None:
        pattern_checks = {
            "empty_parts": True,
            "whitespace": True,
            "consecutive_dots": True
        }
    
    if format_options is None:
        format_options = {
            "check_empty_parts": True,
            "check_whitespace": True,
            "check_pattern": True
        }
    
    if local_part_options is None:
        local_part_options = {
            "check_consecutive_dots": True,
            "check_chars_strict": True,
            "allowed_chars": "!#$%&'*+-/=?^_`{|}~."
        }
    
    if domain_options is None:
        domain_options = {
            "require_dot": True,
            "check_hyphens": True,
            "check_chars": True,
            "check_consecutive_dots": True,
            "allowed_chars": ".-"
        }
    
    if idna_options is None:
        idna_options = {
            "encode_unicode": True,
            "validate_idna": True
        }
    
    try:
        # Convert all configuration to JSON strings
        main_settings_json = json.dumps(main_settings)
        validation_steps_json = json.dumps(validation_steps)
        pattern_checks_json = json.dumps(pattern_checks)
        format_options_json = json.dumps(format_options)
        local_part_options_json = json.dumps(local_part_options)
        domain_options_json = json.dumps(domain_options)
        idna_options_json = json.dumps(idna_options)
        regex_patterns_json = json.dumps(regex_patterns)
        
        # Check if there's an existing record with nr=1
        existing = sync_db.fetchrow("SELECT nr FROM email_filter_regex_settings WHERE nr = 1")
        
        if existing:
            # Update existing record
            sync_db.execute("""
                UPDATE email_filter_regex_settings SET
                    name = $1,
                    main_settings = $2,
                    validation_steps = $3,
                    pattern_checks = $4,
                    format_options = $5,
                    local_part_options = $6,
                    domain_options = $7,
                    idna_options = $8,
                    regex_pattern = $9,
                    updated_at = CURRENT_TIMESTAMP
                WHERE nr = 1
            """, name, main_settings_json, validation_steps_json, pattern_checks_json, format_options_json,
            local_part_options_json, domain_options_json, idna_options_json, regex_patterns_json)
            
            logger.info(f"Updated email filter regex configuration '{name}'")
        else:
            # Insert new record
            sync_db.execute("""
                INSERT INTO email_filter_regex_settings
                (nr, name, main_settings, validation_steps, pattern_checks, format_options, 
                 local_part_options, domain_options, idna_options, regex_pattern, created_at)
                VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
            """, name, main_settings_json, validation_steps_json, pattern_checks_json, format_options_json,
            local_part_options_json, domain_options_json, idna_options_json, regex_patterns_json)
            
            logger.info(f"Created new email filter regex configuration '{name}'")
        return True
    
    except Exception as e:
        logger.error(f"Error creating email filter regex configuration: {e}")
        return False
