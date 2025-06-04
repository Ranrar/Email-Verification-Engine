"""
Email Verification Engine
===================================
Settings management for Email Verification Engine.
Provides functionality to retrieve and update application settings
from various database tables.
"""

import eel
from src.helpers.dbh import sync_db
from src.managers.log import Axe
from typing import Dict, Any, List, Optional
# Import the auto_tune function from executor
from src.managers.executor import auto_tune

logger = Axe()

@eel.expose
def get_app_settings():
    """Retrieve all application settings from the app_settings table"""
    try:
        settings = sync_db.fetch(
            "SELECT id, category, sub_category, name, value, description FROM app_settings ORDER BY category, sub_category, name"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching app settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_rate_limits():
    """Retrieve all rate limit settings from the rate_limit table"""
    try:
        settings = sync_db.fetch(
            "SELECT id, category, name, value, is_time, enabled, description FROM rate_limit ORDER BY category, name"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching rate limits: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_dns_settings():
    """Retrieve all DNS settings from the dns_settings table"""
    try:
        settings = sync_db.fetch(
            "SELECT id, name, value, is_time, description FROM dns_settings ORDER BY name"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching DNS settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_executor_pool_settings():
    """Retrieve all executor pool settings"""
    try:
        settings = sync_db.fetch(
            "SELECT name, value, is_time, description FROM executor_pool_settings ORDER BY name"
        )
        presets = sync_db.fetch(
            "SELECT name, settings_json, description FROM executor_pool_presets ORDER BY name"
        )
        return {
            "success": True,
            "settings": settings,
            "presets": presets
        }
    except Exception as e:
        logger.error(f"Error fetching executor pool settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_executor_settings():
    """Retrieve all executor pool settings, using executor.py implementation"""
    try:
        # Import the function from executor module
        from src.managers.executor import get_executor_settings as get_raw_settings
        
        # Get basic settings using the executor's implementation
        raw_settings = get_raw_settings()
        
        # Fetch additional data needed for the UI (presets)
        presets = sync_db.fetch(
            "SELECT name, settings_json, description FROM executor_pool_presets ORDER BY name"
        )
        
        # Format settings for UI compatibility
        settings = []
        for name, value in raw_settings.items():
            # Get description (optional query)
            desc_row = sync_db.fetchrow(
                "SELECT description, is_time FROM executor_pool_settings WHERE name = $1",
                name
            )
            description = desc_row['description'] if desc_row else ''
            is_time = desc_row['is_time'] if desc_row else False
            
            settings.append({
                'name': name,
                'value': str(value),
                'is_time': is_time,
                'description': description
            })
        
        return {
            "success": True,
            "settings": settings,
            "presets": presets
        }
    except Exception as e:
        logger.error(f"Error fetching executor settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_app_setting(id: int, value: str):
    """Update a specific app setting by ID"""
    try:
        # First, get the name of the setting being updated
        setting = sync_db.fetchrow(
            "SELECT name FROM app_settings WHERE id = $1",
            id
        )
        
        # Check if this is a protected field
        if setting and setting['name'].lower() in ['name', 'url', 'version']:
            logger.warning(f"Attempted update to read-only setting '{setting['name']}' (id={id}) was blocked")
            return {
                "success": False,
                "error": "This setting is read-only and cannot be modified"
            }
        
        # If we get here, it's not a protected field, so proceed with the update
        sync_db.execute(
            "UPDATE app_settings SET value = $1 WHERE id = $2",
            value, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating app setting (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_rate_limit(id: int, value: str, enabled: bool):
    """Update a specific rate limit setting by ID"""
    try:
        # Convert string value to integer
        int_value = int(value)
        
        sync_db.execute(
            "UPDATE rate_limit SET value = $1, enabled = $2 WHERE id = $3",
            int_value, enabled, id
        )
        return {"success": True}
    except ValueError as e:
        logger.error(f"Error converting value to integer (id={id}, value='{value}'): {str(e)}")
        return {
            "success": False,
            "error": f"Invalid value: '{value}' cannot be converted to integer"
        }
    except Exception as e:
        logger.error(f"Error updating rate limit (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_dns_setting(id: int, value: str):
    """Update a specific DNS setting by ID"""
    try:
        sync_db.execute(
            "UPDATE dns_settings SET value = $1 WHERE id = $2",
            value, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating DNS setting ({id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_executor_pool_setting(name: str, value: int):
    """Update a specific executor pool setting by name"""
    try:
        sync_db.execute(
            "UPDATE executor_pool_settings SET value = $1 WHERE name = $2",
            value, name
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating executor pool setting (name={name}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def apply_executor_pool_preset(preset_name: str):
    """Apply an executor pool preset configuration"""
    try:
        # Get the preset JSON
        preset = sync_db.fetchrow(
            "SELECT settings_json FROM executor_pool_presets WHERE name = $1",
            preset_name
        )
        
        if not preset or not preset.get('settings_json'):
            return {
                "success": False,
                "error": f"Preset '{preset_name}' not found"
            }
        
        # Update each setting from the preset
        settings = preset['settings_json']
        for setting_name, setting_value in settings.items():
            sync_db.execute(
                "UPDATE executor_pool_settings SET value = $1 WHERE name = $2",
                setting_value, setting_name
            )
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Error applying executor pool preset (name={preset_name}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Validation Scoring Functions
@eel.expose
def get_validation_scoring():
    """Retrieve all validation scoring settings"""
    try:
        settings = sync_db.fetch(
            "SELECT id, check_name, score_value, is_penalty, description FROM validation_scoring ORDER BY check_name"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching validation scoring settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_validation_scoring(id: int, score_value: int, is_penalty: bool):
    """Update a specific validation scoring setting by ID"""
    try:
        sync_db.execute(
            "UPDATE validation_scoring SET score_value = $1, is_penalty = $2 WHERE id = $3",
            score_value, is_penalty, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating validation scoring (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Confidence Levels Functions
@eel.expose
def get_confidence_levels():
    """Retrieve all confidence level settings"""
    try:
        settings = sync_db.fetch(
            "SELECT id, level_name, min_threshold, max_threshold, description FROM confidence_levels ORDER BY min_threshold"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching confidence level settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_confidence_level(id: int, min_threshold: int, max_threshold: int):
    """Update a specific confidence level setting by ID"""
    try:
        sync_db.execute(
            "UPDATE confidence_levels SET min_threshold = $1, max_threshold = $2 WHERE id = $3",
            min_threshold, max_threshold, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating confidence level (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Ports Configuration Functions
@eel.expose
def get_ports_configuration():
    """Retrieve all port configuration settings"""
    try:
        settings = sync_db.fetch(
            "SELECT id, category, port, priority, enabled, description FROM ports ORDER BY category, priority"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching port configuration settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_port(id: int, priority: int, enabled: bool):
    """Update a specific port setting by ID"""
    try:
        sync_db.execute(
            "UPDATE ports SET priority = $1, enabled = $2 WHERE id = $3",
            priority, enabled, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating port configuration (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Email Filter Regex Functions
@eel.expose
def get_email_filter_regex_settings():
    """Retrieve all email filter regex settings"""
    try:
        settings = sync_db.fetch(
            "SELECT id, nr, name, main_settings, validation_steps, pattern_checks, format_options, " +
            "local_part_options, domain_options, idna_options, regex_pattern, updated_at, created_at " +
            "FROM email_filter_regex_settings ORDER BY nr"
        )
        return {
            "success": True,
            "settings": settings
        }
    except Exception as e:
        logger.error(f"Error fetching email filter regex settings: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_email_filter_regex_presets():
    """Retrieve all email filter regex presets"""
    try:
        settings = sync_db.fetch(
            "SELECT id, name, main_settings_config, validation_steps_config, pattern_checks_config, " +
            "format_options_config, local_part_options_config, domain_options_config, " +
            "idna_options_config, regex_pattern_config, description, created_at " +
            "FROM email_filter_regex_presets ORDER BY name"
        )
        return {
            "success": True,
            "presets": settings
        }
    except Exception as e:
        logger.error(f"Error fetching email filter regex presets: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_email_filter_regex_setting(id: int, settings_data: Dict[str, Any]):
    """Update a specific email filter regex setting by ID"""
    try:
        # Extract individual settings from the settings_data dictionary
        main_settings = settings_data.get('main_settings')
        validation_steps = settings_data.get('validation_steps')
        pattern_checks = settings_data.get('pattern_checks')
        format_options = settings_data.get('format_options')
        local_part_options = settings_data.get('local_part_options')
        domain_options = settings_data.get('domain_options')
        idna_options = settings_data.get('idna_options')
        regex_pattern = settings_data.get('regex_pattern')
        
        sync_db.execute(
            """UPDATE email_filter_regex_settings SET 
               main_settings = $1, validation_steps = $2, pattern_checks = $3,
               format_options = $4, local_part_options = $5, domain_options = $6,
               idna_options = $7, regex_pattern = $8, updated_at = NOW()
               WHERE id = $9""",
            main_settings, validation_steps, pattern_checks, format_options,
            local_part_options, domain_options, idna_options, regex_pattern, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating email filter regex setting (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def apply_email_filter_regex_preset(preset_id: int):
    """Apply an email filter regex preset configuration"""
    try:
        # Get the preset configuration
        preset = sync_db.fetchrow(
            """SELECT name, main_settings_config, validation_steps_config, pattern_checks_config,
               format_options_config, local_part_options_config, domain_options_config,
               idna_options_config, regex_pattern_config, description
               FROM email_filter_regex_presets WHERE id = $1""",
            preset_id
        )
        
        if not preset:
            return {
                "success": False,
                "error": f"Preset with ID {preset_id} not found"
            }
        
        # Update the current settings with the preset
        sync_db.execute(
            """UPDATE email_filter_regex_settings SET 
               name = $1, main_settings = $2, validation_steps = $3, pattern_checks = $4,
               format_options = $5, local_part_options = $6, domain_options = $7,
               idna_options = $8, regex_pattern = $9, updated_at = NOW() 
               WHERE nr = 1""",  # Always update the active configuration
            preset['name'], preset['main_settings_config'], preset['validation_steps_config'], 
            preset['pattern_checks_config'], preset['format_options_config'], 
            preset['local_part_options_config'], preset['domain_options_config'],
            preset['idna_options_config'], preset['regex_pattern_config']
        )
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Error applying email filter regex preset (id={preset_id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Domain Black/White List Functions
@eel.expose
def get_black_white_list():
    """Retrieve the domain black/white list"""
    try:
        # Import time formatting utilities
        from src.managers.time import to_iso8601, normalize_datetime
        
        # Fetch the domains
        domains = sync_db.fetch(
            "SELECT id, domain, category, timestamp, added_by FROM black_white ORDER BY domain"
        )
        
        # Format timestamps to ISO8601 format for JavaScript
        for domain in domains:
            if domain['timestamp']:
                # Normalize and format to ISO8601
                normalized_time = normalize_datetime(domain['timestamp'])
                domain['timestamp'] = to_iso8601(normalized_time)
        
        return {
            "success": True,
            "domains": domains
        }
    except Exception as e:
        logger.error(f"Error fetching black/white list: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def add_domain_to_list(domain: str, category: str, added_by: str):
    """Add a domain to the black/white list"""
    try:
        # Validate category
        if category not in ['blacklisted', 'whitelisted']:
            return {
                "success": False,
                "error": "Category must be either 'blacklisted' or 'whitelisted'"
            }
        
        sync_db.execute(
            "INSERT INTO black_white (domain, category, added_by) VALUES ($1, $2, $3) " +
            "ON CONFLICT (domain) DO UPDATE SET category = $2, added_by = $3, timestamp = NOW()",
            domain, category, added_by
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error adding domain to black/white list: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def remove_domain_from_list(id: int):
    """Remove a domain from the black/white list"""
    try:
        sync_db.execute(
            "DELETE FROM black_white WHERE id = $1",
            id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error removing domain from black/white list (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def update_domain_category(id: int, category: str):
    """Update the category of a domain in the black/white list"""
    try:
        # Validate category
        if category not in ['blacklisted', 'whitelisted']:
            return {
                "success": False,
                "error": "Category must be either 'blacklisted' or 'whitelisted'"
            }
            
        sync_db.execute(
            "UPDATE black_white SET category = $1, timestamp = NOW() WHERE id = $2",
            category, id
        )
        return {"success": True}
    except Exception as e:
        logger.error(f"Error updating domain category (id={id}): {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Executor Autotune Function
@eel.expose
def run_executor_autotune(apply_settings=True):
    """Run executor autotune to optimize thread and process pool settings"""
    try:
        # Call the auto_tune function from executor.py
        results = auto_tune(
            apply_settings=apply_settings,
            print_output=False,
            run_type="ui_request",
            notes="Initiated from settings UI",
            show_results_recommended=False
        )
        
        return {
            "success": True,
            "results": results
        }
    except Exception as e:
        logger.error(f"Error running executor autotune: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@eel.expose
def get_executor_presets():
    """Retrieve all executor pool presets"""
    try:
        presets = sync_db.fetch(
            "SELECT id, name, settings_json, description FROM executor_pool_presets ORDER BY name"
        )
        return {
            "success": True,
            "presets": presets
        }
    except Exception as e:
        logger.error(f"Error fetching executor presets: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }