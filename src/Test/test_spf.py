import sys
import os
# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
import json
from datetime import datetime
from typing import Dict, Any, List

# Import SPF functionality
from src.engine.functions.spf import spf_check, SPFValidator, SPFResult
from src.managers.log import Axe

# Initialize logger
logger = Axe()

def run_spf_test(test_cases: List[Dict[str, Any]]) -> None:
    """
    Run SPF tests on provided test cases
    
    Args:
        test_cases: List of test case dictionaries
    """
    print("\n===== SPF VALIDATION TEST =====")
    print(f"Running tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Create SPF validator
    validator = SPFValidator()
    
    # Track test results
    passed = 0
    failed = 0
    
    for idx, test in enumerate(test_cases, 1):
        email = test["email"]
        sender_ip = test.get("sender_ip", "203.0.113.1")  # Default test IP from RFC 5737
        expected_result = test.get("expected_result")
        trace_id = f"test-{idx}-{email.split('@')[1]}"
        
        print(f"\n[Test {idx}] {email} from IP {sender_ip}")
        print(f"Expected: {expected_result}")
        
        try:
            # Run SPF check
            context = {
                "email": email,
                "trace_id": trace_id,
                "sender_ip": sender_ip
            }
            
            result = spf_check(context)
            
            # Display results
            print(f"SPF Result: {result['spf_result']}")
            print(f"SPF Record: {result['spf_record']}")
            print(f"Reason: {result['spf_reason']}")
            
            if "mechanism_matched" in result:
                print(f"Mechanism Matched: {result.get('spf_mechanism_matched', 'None')}")
                
            print(f"DNS Lookups: {result.get('spf_dns_lookups', 0)}")
            print(f"Valid: {result.get('valid', False)}")
            
            # Check if the result matches expectation
            if expected_result and result["spf_result"] == expected_result:
                print("✅ Test PASSED")
                passed += 1
            elif expected_result:
                print("❌ Test FAILED - Result doesn't match expectation")
                failed += 1
            else:
                print("ℹ️ No expected result specified")
                
        except Exception as e:
            print(f"❌ Test ERROR: {str(e)}")
            failed += 1
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"Test Summary: {passed} passed, {failed} failed")
    print("=" * 60)

def test_direct_validation() -> None:
    """Test direct validation using SPFValidator"""
    print("\n===== DIRECT SPF VALIDATION TEST =====")
    
    # Test emails and IPs
    test_cases = [
        {"domain": "gmail.com", "ip": "64.233.160.0", "sender": "test@gmail.com"},
        {"domain": "yahoo.com", "ip": "74.6.231.20", "sender": "test@yahoo.com"},
        {"domain": "outlook.com", "ip": "40.92.0.10", "sender": "test@outlook.com"},
        # Test non-matching IP
        {"domain": "gmail.com", "ip": "192.0.2.1", "sender": "test@gmail.com"}
    ]
    
    validator = SPFValidator()
    
    for idx, test in enumerate(test_cases, 1):
        print(f"\n[Direct Test {idx}] {test['domain']} with IP {test['ip']}")
        
        try:
            result = validator.validate_spf(
                ip=test["ip"],
                sender=test["sender"],
                trace_id=f"direct-test-{idx}"
            )
            
            print(f"Result: {result.result}")
            print(f"Reason: {result.reason}")
            print(f"Mechanism Matched: {result.mechanism_matched}")
            print(f"DNS Lookups: {result.dns_lookups}")
            print(f"Processing Time: {result.processing_time_ms:.2f} ms")
            
        except Exception as e:
            print(f"Error: {str(e)}")

def main() -> None:
    """Main test runner"""
    # Define test cases with known good IP addresses
    test_cases = [
        {"email": "test@gmail.com", "sender_ip": "64.233.160.0", "expected_result": "pass"},
        {"email": "test@outlook.com", "sender_ip": "40.92.0.10", "expected_result": "pass"},
        {"email": "test@apple.com", "sender_ip": "17.172.224.47", "expected_result": "pass"},
        {"email": "test@salesforce.com", "sender_ip": "96.43.144.0", "expected_result": "pass"},
        {"email": "user@example.com", "sender_ip": "203.0.113.1", "expected_result": "fail"},
        {"email": "user@mail.example.com", "sender_ip": "192.0.2.2", "expected_result": "pass"}
    ]
    
    # Run tests with provided IP addresses
    run_spf_test(test_cases)
    
    # Add some additional test cases with non-matching IPs
    additional_test_cases = [
        {"email": "test@gmail.com", "sender_ip": "192.0.2.1", "expected_result": "softfail"},
        {"email": "test@microsoft.com", "sender_ip": "203.0.113.1", "expected_result": "fail"},
        {"email": "test@nonexistent-domain-12345.com", "sender_ip": "203.0.113.1", "expected_result": "temperror"}
    ]
    
    # Run additional tests
    print("\n----- Additional Tests with Non-Matching IPs -----")
    run_spf_test(additional_test_cases)
    
    # Run direct validation tests
    test_direct_validation()

if __name__ == "__main__":
    main()