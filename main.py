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

Email Verification Engine V 0.2
Copytight © 2025 by Kim Skov Rasmussen
https://github.com/Ranrar
Read licens before use
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
        
        # Format the response for the frontend
        response = {
            "valid": validation_result.get("is_valid", False),
            "message": "Email is valid." if validation_result.get("is_valid") else "Email is invalid.",
            "details": {
                "confidence_score": validation_result.get("confidence_score", 0),
                "confidence_level": validation_result.get("confidence_level", "Low"),
                "smtp_verified": validation_result.get("smtp_result", False),
                "is_disposable": validation_result.get("is_disposable", False),
                "mx_records": validation_result.get("mx_records", []),
                "domain": validation_result.get("domain", ""),
                "trace_id": validation_result.get("trace_id", "")
            }
        }
        
        print(f"Email validation completed for {email}: {response['valid']}")
        return response
        
    except Exception as e:
        print(f"Error verifying email {email}: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "valid": False,
            "message": f"Error: {str(e)}",
            "details": {
                "confidence_score": 0,
                "confidence_level": "Error",
                "smtp_verified": False,
                "is_disposable": False,
                "mx_records": [],
                "domain": email.split("@")[1] if "@" in email else "",
                "trace_id": ""
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