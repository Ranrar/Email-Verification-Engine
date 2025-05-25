"""
SMTP Validation Tester for Email Verification Engine
===================================================

This script tests the SMTP validation functionality of the Email Verification Engine.
It verifies mailbox existence by connecting to SMTP servers and checking responses.

Usage:
  # From project root
  python src/Test/test_smtp.py test@example.com
  
  # Run with detailed statistics
  python src/Test/test_smtp.py test@example.com --stats

   # Run display results
  python src/Test/test_smtp.py test@example.com --verbose

  # Run with sample emails
  python src/Test/test_smtp.py
"""

import sys
import os
import json
import time
from datetime import datetime
from pprint import pprint

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.engine.functions.smtp import validate_email, SMTPValidator
from src.managers.log import Axe
from src.helpers.dbh import sync_db

# Initialize logger
logger = Axe()

def test_smtp(email, verbose=False, show_stats=False):
    """
    Test SMTP validation for an email address.
    
    Args:
        email: Email address to validate
        verbose: Whether to show detailed connection information
        show_stats: Whether to show domain statistics after validation
    """
    print(f"\nTesting SMTP validation for: {email}")
    
    # Create a trace ID for tracking
    trace_id = f"test-smtp-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Create context dictionary with test_mode enabled
    context = {
        "email": email,
        "trace_id": trace_id,
        "test_mode": True  # Enable test mode to bypass rate limits
    }
    
    # Get domain for statistics
    domain = email.split('@')[1] if '@' in email else None
    
    # Show domain statistics before validation if requested
    if show_stats and domain:
        print("\n📊 PRIOR DOMAIN STATISTICS:")
        display_domain_stats(domain)
        
    # Record start time
    start_time = time.time()
    print("Starting SMTP validation...")
    
    # Call the validation function
    result = validate_email(context)
    
    # Calculate elapsed time if not included in result
    if 'execution_time' not in result:
        result['execution_time'] = (time.time() - start_time) * 1000
    
    # Display results
    display_smtp_results(result, verbose)
    
    # Show domain statistics after validation if requested
    if show_stats and domain:
        print("\n📊 UPDATED DOMAIN STATISTICS:")
        display_domain_stats(domain)
        
    return result

def display_domain_stats(domain):
    """Display statistics for a domain from the database"""
    try:
        # Get domain stats
        stats = sync_db.fetchrow(
            """
            SELECT * FROM smtp_domain_stats 
            WHERE domain = $1
            """, 
            domain  # Remove parentheses - don't pass as tuple
        )
        
        if not stats:
            print(f"No statistics available for {domain}")
            return
            
        print("-"*50)
        print(f"Domain: {stats.get('domain', domain)}")
        print(f"Total attempts: {stats.get('total_attempts', 0)}")
        print(f"Success rate: {stats.get('success_rate', 0):.2f}%")
        print(f"Response times: avg={stats.get('avg_response_time_ms', 0)}ms, "
              f"min={stats.get('min_response_time_ms', 0)}ms, "
              f"max={stats.get('max_response_time_ms', 0)}ms")
        
        if stats.get('is_problematic'):
            print("⚠️ This domain is marked as PROBLEMATIC")
            
        # Show geographic info
        geo_info = []
        if stats.get('country_code'):
            geo_info.append(f"Country: {stats.get('country_code')}")
        if stats.get('region'):
            geo_info.append(f"Region: {stats.get('region')}")
        if stats.get('detected_provider'):
            geo_info.append(f"Provider: {stats.get('detected_provider')}")
            
        if geo_info:
            print(f"📍 Geographic info: {', '.join(geo_info)}")
            
        # Show backoff info
        retry_time = stats.get('retry_available_after')
        if retry_time is not None:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            
            if retry_time > now:
                wait_seconds = int((retry_time - now).total_seconds())
                print(f"⏳ In backoff: Level {stats.get('current_backoff_level', 0)}, "
                      f"wait {wait_seconds}s before next attempt")
            else:
                print(f"Previous backoff level: {stats.get('current_backoff_level', 0)}")
                
        # Show adaptive timing
        if stats.get('timeout_adjustment_factor', 0) != 1.0:
            print(f"⚡ Timeout adjustment factor: {stats.get('timeout_adjustment_factor', 1.0):.2f}x")
            
        # Show recent failures
        if stats.get('consecutive_failures', 0) > 0:
            print(f"❌ Consecutive failures: {stats.get('consecutive_failures', 0)}")
            
        print("-"*50)
        
    except Exception as e:
        print(f"Error retrieving domain statistics: {e}")

def display_smtp_results(result, verbose=False):
    """Display SMTP validation results in a readable format"""
    print("\n" + "="*50)
    print(" 📧 SMTP VALIDATION RESULTS")
    print("="*50)
    
    # Display summary
    valid = result.get('valid', False)
    deliverable = result.get('is_deliverable', False)
    
    # Show validation status with emoji
    if valid:
        print("✅ Email VALID")
        print("📬 Mailbox EXISTS")
    else:
        print("❌ Email INVALID")
        print("📪 Mailbox does NOT exist or cannot be verified")
    
    # Show error if any
    if 'error' in result and result['error']:
        print(f"🚫 Error: {result['error']}")
        
        # Show error context if available
        if 'error_context' in result:
            print(f"   Context: {result['error_context']}")
    
    # Show execution time
    print(f"⏱️  Execution time: {result.get('execution_time', 0):.2f} ms")
    
    # Get details
    details = result.get('details', {})
    
    if not details:
        print("\nNo additional details available.")
        return
        
    print("\n📊 VALIDATION DETAILS:")
    print("-"*50)
    
    # Show backoff information
    if details.get('in_backoff'):
        print(f"⚠️ Domain in backoff period until: {details.get('retry_after', 'unknown')}")
        print(f"   Remaining wait time: {details.get('wait_seconds', 0)} seconds")
        print(f"   Reason: {details.get('backoff_reason', 'unknown')}")
    
    # Show connection stats
    print(f"MX servers tried: {details.get('mx_servers_tried', 0)}")
    print(f"SMTP ports tried: {details.get('ports_tried', 0)}")
    
    # Show connection results
    if details.get('connection_success'):
        print("✓ Successfully connected to SMTP server")
        
        # Show which port was used
        if 'port' in details:
            print(f"✓ Connected on port {details['port']}")
        
        # Show SMTP capabilities
        capabilities = []
        if details.get('supports_starttls'):
            capabilities.append("STARTTLS")
        if details.get('supports_auth'):
            capabilities.append("AUTH")
        if details.get('vrfy_supported'):
            capabilities.append("VRFY")
        
        if capabilities:
            print(f"Server capabilities: {', '.join(capabilities)}")
        
        # Show SMTP flow results
        if details.get('smtp_flow_success'):
            print("✓ SMTP conversation successful")
        else:
            print("✗ SMTP conversation failed")
            
            # Show SMTP error code if available
            if 'smtp_error_code' in details:
                code = details['smtp_error_code']
                print(f"SMTP error code: {code}")
                
                # Provide explanation for common error codes
                explanations = {
                    550: "Mailbox unavailable/does not exist",
                    551: "User not local or invalid address",
                    552: "Mailbox storage limit exceeded",
                    553: "Mailbox name invalid",
                    450: "Mailbox busy or temporarily unavailable (possible greylisting)",
                    451: "Local error in processing",
                    452: "Insufficient system storage",
                    421: "Service not available, closing transmission channel",
                    500: "Syntax error, command unrecognized",
                    501: "Syntax error in parameters or arguments",
                    503: "Bad sequence of commands",
                    554: "Transaction failed"
                }
                
                if code in explanations:
                    print(f"Explanation: {explanations[code]}")
    else:
        print("✗ Failed to connect to SMTP server")
    
    # Show server message
    server_msg = details.get('server_message', '')
    if server_msg and server_msg.strip():
        print("\nServer response message:")
        print(f"\"{server_msg.strip()}\"")
    
    # Show additional details in verbose mode
    if verbose:
        print("\n🔍 TECHNICAL DETAILS:")
        
        # Show SMTP banner
        banner = details.get('smtp_banner', '')
        if banner:
            print(f"\nSMTP Banner: \"{banner.strip()}\"")
        
        # Show errors
        errors = details.get('errors', [])
        if errors:
            print("\nErrors encountered:")
            for i, err in enumerate(errors, 1):
                print(f"  {i}. {err}")

def main():
    """Main function to handle command-line arguments"""
    # Parse command line arguments
    show_stats = '--stats' in sys.argv
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    
    # Check if email is provided as command line argument
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        email = sys.argv[1]
        test_smtp(email, verbose, show_stats)
    else:
        # Use sample emails
        sample_emails = [
            # Valid popular email domains
            "test@gmail.com",
            "info@microsoft.com",
            
            # Valid but likely non-existent addresses
            "nonexistent123456789@gmail.com",
            
            # Invalid email format
            "invalid-email",
            
            # Non-existent domain
            "test@nonexistentdomain123456789.com",
            
            # Example domain
            "test@example.com"
        ]
        
        print("No email provided. Testing with sample emails...")
        
        for i, email in enumerate(sample_emails, 1):
            print(f"\n{'#'*70}")
            print(f"TEST {i}/{len(sample_emails)}: {email}")
            print(f"{'#'*70}")
            try:
                test_smtp(email, verbose, show_stats)
            except Exception as e:
                print(f"Error testing {email}: {e}")
            
            # Pause between tests to avoid rate limiting
            if i < len(sample_emails):
                print("\nPausing for 1 second before next test...")
                time.sleep(1)

if __name__ == "__main__":
    main()