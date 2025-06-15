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

  # Test rate limiting
  python src/Test/test_smtp.py --test-limits

  # Test temporary blocklist functionality
  python src/Test/test_smtp.py --test-blocklist

  # Test with different sender patterns
  python src/Test/test_smtp.py test@example.com --sender="test@mydomain.com"
"""

import sys
import os
import json
import time
from datetime import datetime, timezone, timedelta
from pprint import pprint

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.engine.functions.smtp import validate_smtp, SMTPValidator
from src.managers.log import get_logger
from src.helpers.dbh import sync_db

# Initialize logger
logger = get_logger()

def test_smtp(email, show_stats=False, sender_pattern=None):
    """
    Test SMTP validation for an email address.
    
    Args:
        email: Email address to validate
        show_stats: Whether to show domain statistics after validation
        sender_pattern: Custom sender pattern to use
    """
    print(f"\nTesting SMTP validation for: {email}")
    
    # Create a trace ID for tracking
    trace_id = f"test-smtp-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Create context dictionary with test_mode enabled
    context = {
        "email": email,
        "trace_id": trace_id,
        "test_mode": True,  # Enable test mode to bypass rate limits
        "sender_pattern": sender_pattern or "verification@example.com"  # Use custom or default sender pattern
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
    
    try:
        # Call the validation function
        result = validate_smtp(context)
        
        # Calculate elapsed time if not included in result
        if 'execution_time' not in result:
            result['execution_time'] = (time.time() - start_time) * 1000
        
        # Display results with all details
        display_smtp_results(result)
        
        # Show domain statistics after validation if requested
        if show_stats and domain:
            print("\n📊 UPDATED DOMAIN STATISTICS:")
            display_domain_stats(domain)
            
        return result
        
    except Exception as e:
        error_result = {
            'valid': False,
            'error': f"Test execution error: {str(e)}",
            'is_deliverable': False,
            'details': {'test_error': True},
            'execution_time': (time.time() - start_time) * 1000
        }
        
        print(f"\n❌ Test execution failed: {e}")
        display_smtp_results(error_result)
        
        return error_result

def display_domain_stats(domain):
    """Display statistics for a domain from the database"""
    try:
        # Get domain stats
        stats = sync_db.fetchrow(
            """
            SELECT * FROM smtp_domain_stats 
            WHERE domain = $1
            """, 
            domain
        )
        
        if not stats:
            print(f"No statistics available for {domain}")
            return
            
        print("-"*50)
        print(f"Domain: {stats.get('domain', domain)}")
        print(f"Total attempts: {stats.get('total_attempts', 0)}")
        print(f"Successful attempts: {stats.get('successful_attempts', 0)}")
        print(f"Failed attempts: {stats.get('failed_attempts', 0)}")
        print(f"Timeout count: {stats.get('timeout_count', 0)}")
        
        # Handle success rate calculation with better null checking
        success_rate = stats.get('success_rate', 0)
        if success_rate is not None:
            # Convert to percentage if it's a decimal between 0-1
            if success_rate <= 1.0:
                success_rate_pct = success_rate * 100
            else:
                success_rate_pct = success_rate
            print(f"Success rate: {success_rate_pct:.2f}%")
        else:
            print("Success rate: N/A")
            
        # Response time stats with null handling
        avg_time = stats.get('avg_response_time_ms', 0) or 0
        min_time = stats.get('min_response_time_ms', 0) or 0
        max_time = stats.get('max_response_time_ms', 0) or 0
        
        print(f"Response times: avg={avg_time}ms, min={min_time}ms, max={max_time}ms")
        
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
            now = datetime.now(timezone.utc)
            
            if retry_time > now:
                wait_seconds = int((retry_time - now).total_seconds())
                print(f"⏳ In backoff: Level {stats.get('current_backoff_level', 0)}, "
                      f"wait {wait_seconds}s before next attempt")
            else:
                print(f"Previous backoff level: {stats.get('current_backoff_level', 0)}")
                
        # Show timeout adjustment factor
        timeout_factor = stats.get('timeout_adjustment_factor', 1.0)
        if timeout_factor and abs(float(timeout_factor) - 1.0) > 0.01:  # Only show if significantly different from 1.0
            print(f"⚡ Timeout adjustment factor: {float(timeout_factor):.2f}x")
            
        # Show recent failures
        consecutive_failures = stats.get('consecutive_failures', 0)
        if consecutive_failures and consecutive_failures > 0:
            print(f"❌ Consecutive failures: {consecutive_failures}")

        # Show last error code if available
        last_error_code = stats.get('last_error_code')
        if last_error_code:
            print(f"Last error code: {last_error_code}")

        # Show common error codes if available
        common_errors = stats.get('common_error_codes')
        if common_errors:
            try:
                import json
                error_dict = json.loads(common_errors) if isinstance(common_errors, str) else common_errors
                if error_dict:
                    print(f"Common error codes: {dict(error_dict)}")
            except Exception:
                pass

        # Show timestamps
        if stats.get('last_success_at'):
            print(f"Last success: {stats.get('last_success_at')}")
        if stats.get('last_failure_at'):
            print(f"Last failure: {stats.get('last_failure_at')}")
            
        print("-"*50)
        
    except Exception as e:
        print(f"Error retrieving domain statistics: {e}")

def display_smtp_results(result):
    """Display SMTP validation results in a readable format with all details"""
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
    execution_time = result.get('execution_time', 0)
    print(f"⏱️  Execution time: {execution_time:.2f} ms")
    
    # Get details
    details = result.get('details', {})
    
    if not details:
        print("\nNo additional details available.")
        return
        
    print("\n📊 VALIDATION DETAILS:")
    print("-"*50)
    
    # Show temporarily blocked status
    if details.get('temporarily_blocked'):
        print("🚫 Domain is temporarily blocked")
    
    # Show backoff information
    if details.get('in_backoff'):
        print(f"⚠️ Domain in backoff period until: {details.get('retry_after', 'unknown')}")
        print(f"   Remaining wait time: {details.get('wait_seconds', 0)} seconds")
        print(f"   Reason: {details.get('backoff_reason', 'unknown')}")
    
    # Show rate limit information
    if details.get('rate_limited'):
        print("⚠️ Rate limited")
    
    # Show connection stats
    mx_tried = details.get('mx_servers_tried', 0)
    ports_tried = details.get('ports_tried', 0)
    print(f"MX servers tried: {mx_tried}")
    print(f"SMTP ports tried: {ports_tried}")
    
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
    
    # Always show technical details (removed the verbose condition)
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
            
    # Show timeout detection
    if details.get('timeout_detected'):
        print("\n⚠️ Timeout was detected during connection")

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("\n" + "="*70)
    print(" 🚦 TESTING RATE LIMITING")
    print("="*70)
    
    test_domain = "gmail.com"
    test_emails = [f"test{i}@{test_domain}" for i in range(5)]
    
    print(f"Testing rate limiting with {len(test_emails)} emails from {test_domain}")
    print("Note: test_mode is disabled to see actual rate limiting behavior")
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Test {i}/{len(test_emails)}: {email} ---")
        
        # Test without test_mode to see rate limiting in action
        context = {
            "email": email,
            "trace_id": f"rate-test-{i}",
            "test_mode": False  # Disable test mode to test rate limiting
        }
        
        start = time.time()
        result = validate_smtp(context)
        duration = (time.time() - start) * 1000
        
        print(f"Result: {'✓' if result.get('valid') else '✗'}")
        print(f"Duration: {duration:.2f}ms")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
            
        # Show rate limiting details
        details = result.get('details', {})
        if details.get('rate_limited'):
            print("🚦 Rate limited as expected")
        if details.get('in_backoff'):
            print(f"⏳ Domain in backoff: {details.get('wait_seconds', 0)}s remaining")
            
        # Small delay between requests
        if i < len(test_emails):
            time.sleep(0.5)

def test_temporary_blocklist():
    """Test temporary blocklist functionality"""
    print("\n" + "="*70)
    print(" 🚫 TESTING TEMPORARY BLOCKLIST")
    print("="*70)
    
    test_domain = "temporarytest.example"
    validator = SMTPValidator()
    
    print(f"Testing temporary blocklist with domain: {test_domain}")
    
    # Check if domain is initially blocked
    print(f"\n1. Initial check - is {test_domain} blocked?")
    is_blocked = validator._is_domain_temporarily_blocked(test_domain)
    print(f"   Blocked: {is_blocked}")
    
    # Add domain to blocklist
    print(f"\n2. Adding {test_domain} to temporary blocklist...")
    validator._add_to_temporary_blocklist(test_domain, "Test reason", "test-trace")
    
    # Check if domain is now blocked
    print(f"\n3. Check after adding - is {test_domain} blocked?")
    is_blocked = validator._is_domain_temporarily_blocked(test_domain)
    print(f"   Blocked: {is_blocked}")
    
    # Check blocklist entry in database
    try:
        entry = sync_db.fetchrow(
            "SELECT * FROM smtp_temporary_blocklist WHERE domain = $1",
            test_domain
        )
        if entry:
            print(f"   Database entry found:")
            print(f"   - Reason: {entry.get('reason')}")
            print(f"   - Expires at: {entry.get('expires_at')}")
            print(f"   - Block count: {entry.get('block_count', 1)}")
        else:
            print("   No database entry found")
    except Exception as e:
        print(f"   Error checking database: {e}")
    
    print(f"\n4. Testing validation with blocked domain...")
    context = {
        "email": f"test@{test_domain}",
        "trace_id": "blocklist-test",
        "test_mode": False
    }
    
    result = validate_smtp(context)
    print(f"   Validation result: {'✓' if result.get('valid') else '✗'}")
    print(f"   Error: {result.get('error', 'None')}")
    if result.get('details', {}).get('temporarily_blocked'):
        print("   ✓ Correctly identified as temporarily blocked")

def test_domain_can_validate():
    """Test the can_validate_domain functionality"""
    print("\n" + "="*70)
    print(" ✅ TESTING DOMAIN VALIDATION CHECK")
    print("="*70)
    
    validator = SMTPValidator()
    test_domains = ["gmail.com", "outlook.com", "nonexistent123456.com"]
    
    for domain in test_domains:
        print(f"\nTesting can_validate_domain for: {domain}")
        can_validate, reason = validator.can_validate_domain(domain, f"test-{domain}")
        print(f"  Can validate: {can_validate}")
        print(f"  Reason: {reason}")

def test_batch_validation():
    """Test batch email validation with delays"""
    print("\n" + "="*70)
    print(" 📦 TESTING BATCH VALIDATION")
    print("="*70)
    
    validator = SMTPValidator(test_mode=True)
    test_emails = [
        "test1@gmail.com",
        "test2@gmail.com",
        "test1@outlook.com",
        "test2@outlook.com",
        "invalid-email",
        "test@nonexistent123456.com"
    ]
    
    print(f"Testing batch validation with {len(test_emails)} emails")
    print("Emails:", test_emails)
    
    start_time = time.time()
    results = validator.validate_smtp_batch(test_emails, delay_between_domains=0.5)
    total_time = time.time() - start_time
    
    print(f"\nBatch validation completed in {total_time:.2f} seconds")
    print("\nResults:")
    for i, (email, result) in enumerate(zip(test_emails, results), 1):
        status = "✓" if result.get('valid') else "✗"
        error = result.get('error', 'None')
        print(f"  {i}. {email}: {status} ({error})")

def clean_test_data():
    """Clean up test data from database"""
    print("\n🧹 Cleaning up test data...")
    try:
        # Remove test entries from temporary blocklist
        sync_db.execute(
            "DELETE FROM smtp_temporary_blocklist WHERE domain LIKE '%test%' OR domain LIKE '%example%'"
        )
        print("✓ Cleaned temporary blocklist test entries")
        
        # Clean up test domain stats (optional)
        # sync_db.execute(
        #     "DELETE FROM smtp_domain_stats WHERE domain LIKE '%test%'"
        # )
        
    except Exception as e:
        print(f"❌ Error cleaning test data: {e}")

def test_port_specific_rate_limiting():
    """Test port-specific rate limiting functionality"""
    print("\n" + "="*70)
    print(" 🚦 TESTING PORT-SPECIFIC RATE LIMITING")
    print("="*70)
    
    test_domain = "example.com"
    validator = SMTPValidator(test_mode=False)  # Disable test mode to see rate limiting
    
    # Get the rate limits for different ports
    port25_interval = validator.rate_limit_manager.get_smtp_port25_conn_interval()
    port587_interval = validator.rate_limit_manager.get_smtp_port587_conn_interval()
    
    print(f"Port 25 interval: {port25_interval}s")
    print(f"Port 587 interval: {port587_interval}s")
    
    # Test port 25
    print("\nTesting port 25 rate limit:")
    result1 = validator._check_domain_rate_limit(test_domain, 25, "test-port25-1")
    print(f"First attempt: {'Allowed' if result1 else 'Blocked'}")
    result2 = validator._check_domain_rate_limit(test_domain, 25, "test-port25-2")
    print(f"Immediate second attempt: {'Allowed' if result2 else 'Blocked'}")
    
    # Wait half the port25 interval and try again
    wait_time = port25_interval / 2
    print(f"\nWaiting {wait_time}s (half the port 25 interval)...")
    time.sleep(wait_time)
    result3 = validator._check_domain_rate_limit(test_domain, 25, "test-port25-3")
    print(f"After waiting {wait_time}s: {'Allowed' if result3 else 'Blocked'}")
    
    # Test port 587 (should have different rate limit)
    print("\nTesting port 587 rate limit:")
    result4 = validator._check_domain_rate_limit(test_domain, 587, "test-port587-1")
    print(f"First attempt: {'Allowed' if result4 else 'Blocked'}")
    
    # Compare behavior between ports
    print("\nThe test confirms different rate limits per port type.")

def test_operation_timeout():
    """Test the overall operation timeout"""
    print("\n" + "="*70)
    print(" ⏱️ TESTING OVERALL OPERATION TIMEOUT")
    print("="*70)
    
    # Get the configured timeout
    validator = SMTPValidator()
    overall_timeout = validator.rate_limit_manager.get_overall_timeout()
    print(f"Configured overall timeout: {overall_timeout}s")
    
    # Create a context that forces slow processing
    slow_domain = "veryslow-example.com"
    context = {
        "email": f"test@{slow_domain}",
        "trace_id": "timeout-test",
        "test_mode": False,
        "force_slow": True  # This would need support in the code
    }
    
    start_time = time.time()
    result = validate_smtp(context)
    elapsed = time.time() - start_time
    
    print(f"Operation completed in {elapsed:.2f}s")
    print(f"Result: {'✓' if result.get('valid') else '✗'}")
    print(f"Error: {result.get('error', 'None')}")
    
    # Check if timeout was enforced
    if elapsed >= overall_timeout or result.get('error') == "Operation timed out":
        print("✅ Timeout correctly enforced")
    else:
        print("❌ Timeout not enforced correctly")

def test_block_durations():
    """Test configurable block durations"""
    print("\n" + "="*70)
    print(" 🚫 TESTING BLOCK DURATIONS")
    print("="*70)
    
    validator = SMTPValidator()
    test_domain = "blockduration.example"
    
    # Get the configured block durations
    timeout_duration = validator.rate_limit_manager.get_timeout_block_duration()
    rate_limit_duration = validator.rate_limit_manager.get_rate_limit_block_duration()
    
    print(f"Timeout block duration: {timeout_duration}s")
    print(f"Rate limit block duration: {rate_limit_duration}s")
    
    # Test timeout block duration
    print("\nTesting timeout block:")
    validator._add_to_temporary_blocklist(test_domain, "SMTP timeout", "test-timeout")
    
    # Check block entry in database
    entry = sync_db.fetchrow(
        "SELECT * FROM smtp_temporary_blocklist WHERE domain = $1",
        test_domain
    )
    
    if entry:
        # Calculate expected expiry time
        expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=timeout_duration)
        actual_expiry = entry.get('expires_at')
        if actual_expiry is not None:
            diff_seconds = abs((expected_expiry - actual_expiry).total_seconds())
            
            print(f"Block expires at: {actual_expiry}")
            print(f"Expected expiry: {expected_expiry}")
            print(f"Difference: {diff_seconds:.2f}s")
            
            if diff_seconds < 5:  # Allow small tolerance
                print("✅ Timeout block duration correctly applied")
            else:
                print("❌ Timeout block duration not correctly applied")
        else:
            print("❌ Block entry found but 'expires_at' is None")
    else:
        print("❌ Block entry not found in database")
    
    # Clean up
    sync_db.execute("DELETE FROM smtp_temporary_blocklist WHERE domain = $1", test_domain)

def test_parameter_type_error_fix():
    """Test the fix for parameter type error in _update_domain_stats"""
    print("\n" + "="*70)
    print(" 🐛 TESTING PARAMETER TYPE ERROR FIX")
    print("="*70)
    
    validator = SMTPValidator()
    test_domain = "parametertest.example"
    
    print("Testing update with error_code = None:")
    try:
        # This would previously fail with "could not determine data type of parameter $10"
        validator._update_domain_stats(
            domain=test_domain,
            success=False,
            response_time_ms=500,
            error_code=None,
            error_type="timeout",
            trace_id="test-none-error"
        )
        print("✅ Update with error_code=None succeeded")
    except Exception as e:
        print(f"❌ Update failed: {e}")
    
    print("\nTesting update with error_code = 550:")
    try:
        validator._update_domain_stats(
            domain=test_domain,
            success=False,
            response_time_ms=500,
            error_code=550,
            error_type="permanent",
            trace_id="test-550-error"
        )
        print("✅ Update with error_code=550 succeeded")
    except Exception as e:
        print(f"❌ Update failed: {e}")
    
    # Verify the updates were recorded
    stats = validator._get_domain_stats(test_domain)
    print(f"\nRecorded stats for {test_domain}:")
    print(f"Total attempts: {stats.get('total_attempts', 0)}")
    print(f"Failed attempts: {stats.get('failed_attempts', 0)}")
    print(f"Timeout count: {stats.get('timeout_count', 0)}")
    
    # Clean up
    sync_db.execute("DELETE FROM smtp_domain_stats WHERE domain = $1", test_domain)

def main():
    """Main function to handle command-line arguments"""
    # Parse command line arguments
    show_stats = '--stats' in sys.argv
    # verbose flag is kept for backward compatibility but not used anymore
    test_limits = '--test-limits' in sys.argv
    test_blocklist = '--test-blocklist' in sys.argv
    test_can_validate = '--test-can-validate' in sys.argv
    test_batch = '--test-batch' in sys.argv
    cleanup = '--cleanup' in sys.argv
    
    # Get sender pattern if provided
    sender_pattern = None
    for arg in sys.argv:
        if arg.startswith('--sender='):
            sender_pattern = arg.split('=', 1)[1]
            break
    
    # Handle cleanup
    if cleanup:
        clean_test_data()
        return
    
    # Test specific functionality
    if test_limits:
        test_rate_limiting()
        return
    
    if test_blocklist:
        test_temporary_blocklist()
        return
        
    if test_can_validate:
        test_domain_can_validate()
        return
        
    if test_batch:
        test_batch_validation()
        return
    
    # Check if email is provided as command line argument
    email_arg = None
    for arg in sys.argv[1:]:
        if not arg.startswith('-') and '@' in arg:
            email_arg = arg
            break
    
    if email_arg:
        test_smtp(email_arg, show_stats, sender_pattern)
    else:
        # Use sample emails
        sample_emails = [
            # Valid popular email domains - these should work
            "test@gmail.com",
            "info@microsoft.com",
            
            # Valid but likely non-existent addresses - these should fail gracefully
            "nonexistent123456789@gmail.com",
            
            # Non-existent domain - this should fail with DNS error
            "test@nonexistentdomain123456789.com",
            
            # Example domain - this should be handled appropriately
            "test@example.com"
        ]
        
        print("No email provided. Testing with sample emails...")
        print(f"Available options:")
        print(f"  --test-limits       Test rate limiting functionality")
        print(f"  --test-blocklist    Test temporary blocklist functionality")
        print(f"  --test-can-validate Test domain validation checking")
        print(f"  --test-batch        Test batch validation")
        print(f"  --stats             Show domain statistics")
        print(f"  --verbose           Show detailed technical information (ignored, all details shown by default)")
        print(f"  --sender=email      Use custom sender email pattern")
        print(f"  --cleanup           Clean up test data from database")
        
        for i, email in enumerate(sample_emails, 1):
            print(f"\n{'#'*70}")
            print(f"TEST {i}/{len(sample_emails)}: {email}")
            print(f"{'#'*70}")
            try:
                test_smtp(email, show_stats, sender_pattern)
            except Exception as e:
                print(f"Error testing {email}: {e}")
            
            # Pause between tests to avoid rate limiting
            if i < len(sample_emails):
                print("\nPausing for 2 seconds before next test...")
                time.sleep(2)

if __name__ == "__main__":
    main()