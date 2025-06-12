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
from src.managers.log import Axe
from src.engine.engine import get_engine
from src.helpers.dbh import sync_db
from src.utils.debug import get_setting, debug_action
from src.utils.purge import purge_and_exit
from src.utils.notifier import Notifier
from src.utils import settings

notify = Notifier()
logger = Axe()

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
                
                # DNS security with enhanced SPF and DMARC details
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

# Add this function to your main.py file

@eel.expose
def get_detailed_validation_data(trace_id):
    """Get detailed validation data for a specific trace ID"""
    try:
        # Dictionary to store results
        results = {}
        
        # Get email validation record
        record = sync_db.fetchrow(
            "SELECT * FROM email_validation_records WHERE trace_id = $1", 
            trace_id
        )
        
        if record:
            # Record is already a dictionary from fetchrow
            results['email_validation_record'] = record
            
            # Format JSON fields properly
            for field in ['mx_analysis', 'email_provider_info', 'raw_result']:
                if field in results['email_validation_record'] and results['email_validation_record'][field]:
                    results['email_validation_record'][field] = json.dumps(results['email_validation_record'][field], indent=2)
        
        # Get MX infrastructure data
        mx_records = sync_db.fetch(
            "SELECT * FROM mx_infrastructure WHERE trace_id = $1",
            trace_id
        )
        
        if mx_records:
            results['mx_infrastructure'] = mx_records
            
            # Format JSON fields properly
            for mx in results['mx_infrastructure']:
                for field in ['ip_addresses', 'ptr_records', 'geo_info', 'whois_summary']:
                    if field in mx and mx[field]:
                        mx[field] = json.dumps(mx[field], indent=2)
        
        # Get IP addresses data
        ip_records = sync_db.fetch(
            "SELECT * FROM mx_ip_addresses WHERE trace_id = $1",
            trace_id
        )
        
        if ip_records:
            results['mx_ip_addresses'] = ip_records
        
        # Get validation steps if you want to include them
        steps = sync_db.fetch(
            "SELECT * FROM validation_steps WHERE trace_id = $1 ORDER BY step_order",
            trace_id
        )
        
        if steps:
            results['validation_steps'] = steps
            
            # Format JSON fields properly
            for step in results['validation_steps']:
                if 'result' in step and step['result']:
                    step['result'] = json.dumps(step['result'], indent=2)
        
        return results
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

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

@eel.expose
def get_dmarc_info(domain):
    """Get detailed DMARC information for a domain"""
    try:
        # Import directly here to avoid circular imports
        from src.engine.functions.dmarc import DMARCValidator
        
        validator = DMARCValidator()
        trace_id = f"dmarc_info_{int(time.time() * 1000)}"
        
        # Validate DMARC for the domain
        dmarc_result = validator.validate_dmarc(domain, trace_id)
        
        # Create a detailed response
        response = {
            "success": True,
            "domain": domain,
            "has_dmarc": dmarc_result.has_dmarc,
            "policy": dmarc_result.policy,
            "policy_strength": dmarc_result.policy_strength,
            "subdomain_policy": dmarc_result.subdomain_policy,
            "alignment_mode": dmarc_result.alignment_mode,
            "percentage_covered": dmarc_result.percentage_covered,
            "aggregate_reporting": dmarc_result.aggregate_reporting,
            "forensic_reporting": dmarc_result.forensic_reporting,
            "organizational_domain": dmarc_result.organizational_domain,
            "recommendations": dmarc_result.recommendations,
            "dns_lookups": dmarc_result.dns_lookups,
            "execution_time_ms": dmarc_result.execution_time_ms,
            "trace_id": trace_id
        }
        
        # Include record details if available
        if dmarc_result.record:
            response["record"] = {
                "raw": dmarc_result.record.raw_record,
                "version": dmarc_result.record.version,
                "rua_addresses": dmarc_result.record.rua_addresses,
                "ruf_addresses": dmarc_result.record.ruf_addresses,
                "failure_options": dmarc_result.record.failure_options,
                "report_format": dmarc_result.record.report_format,
                "report_interval": dmarc_result.record.report_interval
            }
            
        # Include any errors or warnings
        if dmarc_result.errors:
            response["errors"] = dmarc_result.errors
        if dmarc_result.warnings:
            response["warnings"] = dmarc_result.warnings
            
        return response
        
    except Exception as e:
        logger.error(f"Error getting DMARC info for {domain}: {str(e)}", exc_info=True)
        return {
            "success": False,
            "domain": domain,
            "error": str(e)
        }

@eel.expose
def get_dmarc_explanation():
    """Get an explanation of DMARC for users"""
    return {
        "title": "Understanding DMARC",
        "sections": [
            {
                "title": "What is DMARC?",
                "content": "DMARC (Domain-based Message Authentication, Reporting & Conformance) is an email authentication protocol that helps protect email domains from unauthorized use. It builds on SPF and DKIM to provide domain-level protection and reporting."
            },
            {
                "title": "DMARC Policies",
                "content": "DMARC has three policy options: 'none' (monitor only), 'quarantine' (treat suspicious emails with caution), and 'reject' (block suspicious emails). These determine what happens when an email fails DMARC checks."
            },
            {
                "title": "Policy Strength",
                "content": "DMARC policy strength is evaluated as 'none', 'weak', 'moderate', or 'strong' based on the policy type, coverage percentage, alignment settings, and reporting configuration."
            },
            {
                "title": "Reporting",
                "content": "DMARC provides two types of reporting: aggregate reports (rua) give statistical data about email traffic, while forensic reports (ruf) provide details about specific authentication failures."
            }
        ]
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