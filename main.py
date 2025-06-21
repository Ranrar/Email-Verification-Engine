"""
Email Verification Engine
===================================
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░

Email Verification Engine V 0.4
# Copyright (c) 2025 Kim Skov Rasmussen
# This software is licensed under CC BY-NC-ND 4.0.
# Non-commercial academic use only.
# Commercial use prohibited without explicit permission.
"""

import eel
import json
import sys
import threading
import socket
import multiprocessing
import time
from src.helpers.Initialization import start_initialization_process
from src.managers.log import get_logger
from src.engine.engine import get_engine
from src.helpers.dbh import sync_db
from src.utils.debug import get_setting, debug_action
from src.utils.purge import purge_and_exit
from src.utils.notifier import Notifier
from src.utils import settings

notify = Notifier()
logger = get_logger()

# Find an available port
def find_free_port():
    """Find an available port by trying several options"""
    for port in range(8080, 8100):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                print(f"Found available port: {port}")
                return port
        except OSError:
            continue
    
    # If no specific port works, let OS choose one
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]

@eel.expose
def start_initialization():
    """Start the initialization process in a separate thread"""
    threading.Thread(target=start_initialization_process).start()

@eel.expose
def verify_email(email):
    """Verify an email address using the advanced validation engine"""
    try:
        # Get the engine instance
        engine = get_engine()
        
        # Perform validation
        validation_result = engine.validate(email)
        
        # Format the response for the frontend with expanded details
        response = {
            "valid": validation_result.get("is_valid", False),
            "message": "Email is valid." if validation_result.get("is_valid") else "Email is invalid.",
            "details": {
                # Core validation results
                "confidence_score": validation_result.get("confidence_score", 0),
                "confidence_level": validation_result.get("confidence_level", "Low"),
                "is_deliverable": validation_result.get("smtp_result", False),
                "is_format_valid": validation_result.get("is_format_valid", False),
                "execution_time": validation_result.get("execution_time", 0),
                "execution_time_formatted": validation_result.get("execution_time_formatted", ""),
                
                # Domain information
                "domain": validation_result.get("domain", ""),
                "trace_id": validation_result.get("trace_id", ""),
                "mx_records": validation_result.get("mx_records", []),
                "mx_preferences": validation_result.get("mx_preferences", []),
                
                # Classification status
                "is_disposable": validation_result.get("is_disposable", False),
                "catch_all": validation_result.get("catch_all", False),
                
                # DNS security with enhanced SPF, DKIM, and DMARC details
                "dns_security": {
                    "spf": validation_result.get("spf_status", ""),
                    "dkim": validation_result.get("dkim_status", ""),
                    "dmarc": validation_result.get("dmarc_status", ""),
                    # Add detailed SPF information
                    "spf_details": {
                        "spf_record": validation_result.get("spf_details", {}).get("spf_record", ""),
                        "spf_result": validation_result.get("spf_details", {}).get("spf_result", ""),
                        "spf_mechanism_matched": validation_result.get("spf_details", {}).get("spf_mechanism_matched", ""),
                        "spf_dns_lookups": validation_result.get("spf_details", {}).get("spf_dns_lookups", 0),
                        "spf_reason": validation_result.get("spf_details", {}).get("spf_reason", ""),
                        "warnings": validation_result.get("spf_details", {}).get("warnings", []),
                        "errors": validation_result.get("spf_details", {}).get("errors", []),
                        "dns_lookup_log": validation_result.get("spf_details", {}).get("dns_lookup_log", [])
                    },
                    # Add detailed DKIM information
                    "dkim_details": {
                        "has_dkim": validation_result.get("dkim_details", {}).get("has_dkim", False),
                        "selector": validation_result.get("dkim_details", {}).get("selector", ""),
                        "found_selectors": validation_result.get("dkim_details", {}).get("found_selectors", []),
                        "key_type": validation_result.get("dkim_details", {}).get("key_type", ""),
                        "key_length": validation_result.get("dkim_details", {}).get("key_length", 0),
                        "security_level": validation_result.get("dkim_details", {}).get("security_level", "none"),
                        "hash_algorithms": validation_result.get("dkim_details", {}).get("hash_algorithms", []),
                        "testing": validation_result.get("dkim_details", {}).get("testing", False),
                        "recommendations": validation_result.get("dkim_details", {}).get("recommendations", []),
                        "execution_time": validation_result.get("dkim_details", {}).get("execution_time", 0),
                        "warnings": validation_result.get("dkim_details", {}).get("warnings", []),
                        "errors": validation_result.get("dkim_details", {}).get("errors", [])
                    },
                    # Add detailed DMARC information
                    "dmarc_details": {
                        "has_dmarc": validation_result.get("dmarc_details", {}).get("has_dmarc", False),
                        "policy": validation_result.get("dmarc_details", {}).get("policy", "none"),
                        "policy_strength": validation_result.get("dmarc_details", {}).get("policy_strength", "none"),
                        "subdomain_policy": validation_result.get("dmarc_details", {}).get("subdomain_policy", ""),
                        "alignment_mode": validation_result.get("dmarc_details", {}).get("alignment_mode", ""),
                        "percentage_covered": validation_result.get("dmarc_details", {}).get("percentage_covered", 0),
                        "aggregate_reporting": validation_result.get("dmarc_details", {}).get("aggregate_reporting", False),
                        "forensic_reporting": validation_result.get("dmarc_details", {}).get("forensic_reporting", False),
                        "organizational_domain": validation_result.get("dmarc_details", {}).get("organizational_domain", ""),
                        "recommendations": validation_result.get("dmarc_details", {}).get("recommendations", []),
                        "record": validation_result.get("dmarc_details", {}).get("record", ""),
                        "execution_time": validation_result.get("dmarc_details", {}).get("execution_time", 0),
                        "warnings": validation_result.get("dmarc_details", {}).get("warnings", []),
                        "errors": validation_result.get("dmarc_details", {}).get("errors", [])
                    }
                },
                
                # SMTP validation details
                "smtp": {
                    "verified": validation_result.get("smtp_result", False),
                    "error_code": validation_result.get("smtp_error_code"),
                    "server_message": validation_result.get("smtp_server_message", ""),
                    "connection_success": validation_result.get("smtp_flow_success", False),
                    "supports_tls": validation_result.get("smtp_supports_tls", False),
                    "supports_auth": validation_result.get("smtp_supports_auth", False)
                },

                # IMAP details
                "imap": {
                    "status": validation_result.get("imap_status", ""),
                    "details": validation_result.get("imap_details", {})
                },

                # IMAP details
                "pop3": {
                    "status": validation_result.get("pop3_status", ""),
                    "details": validation_result.get("pop3_details", {})
                },

                # Infrastructure information
                "infrastructure": {
                    "provider": validation_result.get("email_provider", {}).get("provider_name", "Unknown"),
                    "self_hosted": validation_result.get("email_provider", {}).get("self_hosted", False),
                    "countries": validation_result.get("infrastructure_info", {}).get("countries", [])
                },
                
                # Blacklist/whitelist information
                "list_status": {
                    "blacklisted": validation_result.get("blacklist_info", {}).get("blacklisted", False),
                    "whitelisted": validation_result.get("blacklist_info", {}).get("whitelisted", False),
                    "source": validation_result.get("blacklist_info", {}).get("source", "")
                },
                
                # Cache information if available
                "cache_info": validation_result.get("cache_info", {})
            }
        }
        
        # Include error message if present
        if validation_result.get("error_message"):
            response["details"]["error_message"] = validation_result.get("error_message")
        
        logger.info(f"Email validation completed for {email}: {response['valid']}")
        return response
        
    except Exception as e:
        logger.error(f"Error verifying email {email}: {str(e)}", exc_info=True)
        return {
            "valid": False,
            "message": f"Error: {str(e)}",
            "details": {
                "confidence_score": 0,
                "confidence_level": "Error",
                "is_deliverable": False,
                "is_format_valid": False,
                "execution_time": 0,
                "execution_time_formatted": "",
                "domain": email.rsplit("@", 1)[1] if "@" in email else "",
                "trace_id": "",
                "mx_records": [],
                "mx_preferences": [],
                "is_disposable": False,
                "catch_all": False,
                "dns_security": {
                    "spf": "",
                    "dkim": "",
                    "dmarc": "",
                    # Add empty DKIM details structure for consistency
                    "dkim_details": {
                        "has_dkim": False,
                        "selector": "",
                        "found_selectors": [],
                        "key_type": "",
                        "key_length": 0,
                        "security_level": "none",
                        "hash_algorithms": [],
                        "testing": False,
                        "recommendations": [],
                        "execution_time": 0,
                        "warnings": [],
                        "errors": [str(e)]
                    },
                    # Add empty DMARC details structure for consistency
                    "dmarc_details": {
                        "has_dmarc": False,
                        "policy": "none",
                        "policy_strength": "none",
                        "alignment_mode": "",
                        "percentage_covered": 0,
                        "aggregate_reporting": False,
                        "forensic_reporting": False,
                        "organizational_domain": "",
                        "recommendations": [],
                        "record": "",
                        "execution_time": 0,
                        "warnings": [],
                        "errors": []
                    }
                },
                "smtp": {  # Add this nested structure 
                    "verified": False,
                    "error_code": None,
                    "server_message": str(e),
                    "connection_success": False,
                    "supports_tls": False,
                    "supports_auth": False
                },
                "infrastructure": {
                    "provider": "Unknown",
                    "self_hosted": False,
                    "countries": []
                },
                "list_status": {
                    "blacklisted": False,
                    "whitelisted": False,
                    "source": ""
                },
                "cache_info": {},
                "error_message": str(e)
            }
        }

@eel.expose
def exit_application():
    """Exit the application"""
    print("Exiting application...")
    sys.exit(0)

@eel.expose
def get_detailed_validation_data(trace_id):
    """Get detailed validation data for a trace ID"""
    try:
        logger.debug(f"Getting detailed validation data for trace_id: {trace_id}")
        
        from src.helpers.dbh import sync_db
        
        # Get validation record from database
        record = None
        try:
            # Try to get email validation record
            result = sync_db.fetch("""
                SELECT * FROM email_validation_records 
                WHERE trace_id = $1 
                ORDER BY timestamp DESC
                LIMIT 1
            """, trace_id)
            
            if result and len(result) > 0:
                record = result[0]
                logger.debug(f"Found email validation record for {trace_id}")
            else:
                logger.warning(f"No validation record found for trace ID: {trace_id}")
                return {
                    'success': False,
                    'error': f"No validation record found for trace ID: {trace_id}"
                }
        except Exception as db_error:
            logger.error(f"Database error retrieving validation record: {db_error}")
            return {
                'success': False,
                'error': f"Database error: {str(db_error)}"
            }
        
        # Get DMARC details
        try:
            if record and record.get('domain'):
                domain = record.get('domain')
                
                # Get DMARC validation statistics
                dmarc_stats = sync_db.fetch("""
                    SELECT * FROM dmarc_validation_statistics 
                    WHERE trace_id = $1 OR domain = $2
                    ORDER BY created_at DESC
                    LIMIT 1
                """, trace_id, domain)
                
                if dmarc_stats and len(dmarc_stats) > 0:
                    dmarc_data = dmarc_stats[0]
                    
                    # Add DMARC data to record
                    if 'dns_security' not in record:
                        record['dns_security'] = {}
                    
                    record['dns_security']['dmarc_details'] = {
                        'has_dmarc': True if dmarc_data.get('raw_record') else False,
                        'policy': dmarc_data.get('policy', 'none'),
                        'policy_strength': dmarc_data.get('policy_strength', 'weak'),
                        'alignment_mode': dmarc_data.get('alignment_mode', 'relaxed'),
                        'raw_record': dmarc_data.get('raw_record', ''),
                        'has_reporting': dmarc_data.get('has_reporting', False),
                        'dns_lookups': dmarc_data.get('dns_lookups', 0),
                        'processing_time_ms': dmarc_data.get('processing_time_ms', 0)
                    }
                    
                    logger.debug(f"Added DMARC details from statistics for {domain}")
        except Exception as dmarc_error:
            logger.warning(f"Error adding DMARC details: {dmarc_error}")
        
        # Get SPF details if available
        try:
            if record and record.get('domain'):
                domain = record.get('domain')
                
                # Get SPF validation statistics
                spf_stats = sync_db.fetch("""
                    SELECT * FROM spf_validation_statistics 
                    WHERE trace_id = $1 OR domain = $2
                    ORDER BY timestamp DESC
                    LIMIT 1
                """, trace_id, domain)
                
                if spf_stats and len(spf_stats) > 0:
                    spf_data = spf_stats[0]
                    
                    # Add SPF data to record
                    if 'dns_security' not in record:
                        record['dns_security'] = {}
                    
                    record['dns_security']['spf_details'] = {
                        'has_spf': True if spf_data.get('raw_record') else False,
                        'result': spf_data.get('result', 'none'),
                        'mechanism_matched': spf_data.get('mechanism_matched', ''),
                        'raw_record': spf_data.get('raw_record', ''),
                        'dns_lookups': spf_data.get('dns_lookups', 0),
                        'processing_time_ms': spf_data.get('processing_time_ms', 0)
                    }
                    
                    logger.debug(f"Added SPF details from statistics for {domain}")
        except Exception as spf_error:
            logger.warning(f"Error adding SPF details: {spf_error}")
        
        # Get DKIM details if available
        try:
            if record and record.get('domain'):
                domain = record.get('domain')
                
                # Get DKIM validation statistics
                dkim_stats = sync_db.fetch("""
                    SELECT * FROM dkim_validation_statistics 
                    WHERE trace_id = $1 OR domain = $2
                    ORDER BY created_at DESC
                    LIMIT 1
                """, trace_id, domain)
                
                if dkim_stats and len(dkim_stats) > 0:
                    dkim_data = dkim_stats[0]
                    
                    # Add DKIM data to record
                    if 'dns_security' not in record:
                        record['dns_security'] = {}
                    
                    record['dns_security']['dkim_details'] = {
                        'has_dkim': True if dkim_data.get('has_dkim', False) else False,
                        'selector': dkim_data.get('selector', ''),
                        'key_type': dkim_data.get('key_type', ''),
                        'key_length': dkim_data.get('key_length', 0),
                        'security_level': dkim_data.get('security_level', 'none'),
                        'dns_lookups': dkim_data.get('dns_lookups', 0),
                        'processing_time_ms': dkim_data.get('processing_time_ms', 0),
                        'errors': dkim_data.get('errors', None)
                    }
                    
                    logger.debug(f"Added DKIM details from statistics for {domain}")
        except Exception as dkim_error:
            logger.warning(f"Error adding DKIM details: {dkim_error}")
        
        # Get MX infrastructure data
        mx_records = []
        try:
            mx_records = sync_db.fetch("""
                SELECT 
                    id, trace_id, domain, mx_record, is_primary, preference, 
                    has_failover, load_balanced, provider_name, is_self_hosted
                FROM mx_infrastructure 
                WHERE trace_id = $1
                ORDER BY preference ASC
            """, trace_id)
            
            # Debug output
            logger.debug(f"MX Query returned {len(mx_records) if mx_records else 0} records for {trace_id}")
            
            # Process the mx_records for UI display - USE THE EXPECTED FIELD NAME
            if mx_records and len(mx_records) > 0:
                # Use mx_infrastructure instead of mx_records_data to match JS expectations
                record['mx_infrastructure'] = mx_records
                logger.debug(f"Added {len(record['mx_infrastructure'])} MX records for {trace_id}")
            else:
                # Provide empty array with the expected field name
                record['mx_infrastructure'] = []
        except Exception as mx_error:
            logger.warning(f"Error retrieving MX infrastructure: {mx_error}")
            record['mx_infrastructure'] = []
        
        # Get IP address data
        ip_data = []
        try:
            ip_data = sync_db.fetch("""
                SELECT 
                    id, trace_id, mx_infrastructure_id, ip_address, ip_version, is_private,
                    ptr_record, country_code, region, provider
                FROM mx_ip_addresses 
                WHERE trace_id = $1
                ORDER BY id
            """, trace_id)
            
            # Debug output
            logger.debug(f"IP Query returned {len(ip_data) if ip_data else 0} records for {trace_id}")
            
            # Process the IP data for UI display - USE THE EXPECTED FIELD NAME
            if ip_data and len(ip_data) > 0:
                # Use mx_ip_addresses instead of ip_addresses_data
                record['mx_ip_addresses'] = ip_data
                logger.debug(f"Added {len(record['mx_ip_addresses'])} IP addresses for {trace_id}")
            else:
                record['mx_ip_addresses'] = []
        except Exception as ip_error:
            logger.warning(f"Error retrieving IP addresses: {ip_error}")
            record['mx_ip_addresses'] = []
        
        # Ensure correct data structure for UI
        return {
            'email_validation_record': record,
            'mx_infrastructure': mx_records,
            'mx_ip_addresses': ip_data,
            'success': True
        }
            
    except Exception as e:
        logger.error(f"Error in get_detailed_validation_data: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            'success': False, 
            'error': str(e)
        }

@eel.expose
def read_markdown_file(filename):
    """Read a markdown file from the root directory or a subdirectory"""
    try:
        import os
        
        # Get the root directory path
        root_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Define the full path to the file
        file_path = os.path.join(root_dir, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return {"success": False, "error": f"File {filename} not found"}
        
        # Read the file content
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
        return {"success": True, "content": content}
    
    except Exception as e:
        return {"success": False, "error": str(e)}

@eel.expose
def list_documentation_files():
    """List all Markdown files in the doc directory"""
    try:
        import os
        
        # Get the root directory path
        root_dir = os.path.dirname(os.path.abspath(__file__))
        doc_dir = os.path.join(root_dir, "doc")
        
        # Check if directory exists
        if not os.path.exists(doc_dir):
            return {
                "success": False,
                "error": f"Documentation directory not found: {doc_dir}"
            }
        
        # List all markdown files
        markdown_files = []
        for file in os.listdir(doc_dir):
            if file.lower().endswith('.md'):
                file_path = os.path.join(doc_dir, file)
                # Get file title from first line if possible
                title = file.replace('.md', '')
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        first_line = f.readline().strip()
                        if first_line.startswith('# '):
                            title = first_line[2:]
                except:
                    pass
                
                markdown_files.append({
                    "name": file,
                    "title": title,
                    "path": os.path.join("doc", file)
                })
        
        # Sort by name
        markdown_files.sort(key=lambda x: x['name'])
        
        return {
            "success": True,
            "files": markdown_files
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# Main function - Non-async for better multiprocessing compatibility
def main():
    # Initialize Eel
    eel.init('src/web')
    
    # Find a free port
    port = find_free_port()
    print(f"Starting Eel on port {port}")
    
    # Start Eel with the port
    try:
        # Use block=True for cleaner operation with multiprocessing
        eel.start('init.html', size=(800, 600), mode='firefox', port=port, block=True)
    except Exception as e:
        print(f"Error starting with firefox: {e}")
        try:
            # Try with default browser
            eel.start('index.html', size=(800, 600), mode=None, port=port, block=True)
        except Exception as e:
            print(f"Failed to start Eel: {e}")

# Entry point
if __name__ == "__main__":
    # This is crucial for multiprocessing on Windows
    multiprocessing.freeze_support()
    
    # Call main directly - no asyncio
    main()