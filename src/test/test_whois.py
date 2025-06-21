"""
Test script for WHOIS functionality in Email Verification Engine.
This script tests the fetch_whois_info function from the mx.py module.

# From project root
# python src/Test/test_whois.py

# Or from Test directory 
# cd src/Test
# python test_whois.py
"""

import sys
import os
import json
from datetime import datetime

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.engine.functions.mx import fetch_whois_info
from src.managers.log import get_logger

# Initialize logger
logger = get_logger()

def test_whois(email):
    """Test the WHOIS functionality with an email address."""
    print(f"Testing WHOIS info for email: {email}")
    
    # Create context dictionary that fetch_whois_info expects
    context = {
        "email": email,
        "trace_id": "test-whois-" + datetime.now().strftime("%Y%m%d%H%M%S")
    }
    
    # Call the function
    print("Fetching WHOIS information...")
    result = fetch_whois_info(context)
    
    # Print results
    print("\n=== WHOIS Results ===")
    print(f"Valid: {result.get('valid')}")
    
    if not result.get('valid'):
        print(f"Error: {result.get('error')}")
        return
        
    print(f"Domain: {result.get('domain')}")
    print(f"Source: {result.get('source')} (cache or direct lookup)")
    
    whois_info = result.get('whois_info', {})
    domain_age = result.get('domain_age_days')
    
    print("\n== WHOIS Information ==")
    
    # Format the output to be more readable
    if whois_info:
        print(f"Registrar: {whois_info.get('registrar', 'N/A')}")
        print(f"Organization: {whois_info.get('organization', 'N/A')}")
        print(f"Country: {whois_info.get('country', 'N/A')}")
        print(f"Creation Date: {whois_info.get('creation_date', 'N/A')}")
        print(f"Expiration Date: {whois_info.get('expiration_date', 'N/A')}")
        
        if domain_age is not None:
            print(f"Domain Age: {domain_age} days")
            years = domain_age // 365
            days = domain_age % 365
            print(f"          ({years} years, {days} days)")
            
        # Print emails if available
        emails = whois_info.get('emails')
        if emails:
            print("\nContact Emails:")
            if isinstance(emails, list):
                for email in emails:
                    print(f"  - {email}")
            else:
                print(f"  - {emails}")
                
        # Print raw data if available
        if 'raw' in whois_info:
            print("\nRaw WHOIS data excerpt:")
            print("-" * 50)
            print(whois_info['raw'][:300] + "..." if len(whois_info['raw']) > 300 else whois_info['raw'])
            print("-" * 50)
    
    # Handle execution time more safely
    exec_time = result.get('execution_time')
    if exec_time is not None:
        print(f"\nExecution time: {float(exec_time):.2f} ms")
    else:
        print("\nExecution time: not available")

if __name__ == "__main__":
    # Check if email is provided as command line argument
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        # Use default test domains
        domains = [
            "example.com",
            "google.com",
            "microsoft.com", 
            "github.com",
            "nonexistentdomainforsure123456789.com"  # Should fail
        ]
        
        print("No email provided. Testing with sample domains...")
        for domain in domains:
            email = f"test@{domain}"
            test_whois(email)
            print("\n" + "="*60 + "\n")
            
        sys.exit(0)
        
    # Test with the provided email
    test_whois(email)
