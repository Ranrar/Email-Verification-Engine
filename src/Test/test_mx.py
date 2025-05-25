"""
MX Record Tester for Email Verification Engine
=============================================

This script tests the MX record lookup functionality of the Email Verification Engine.
It allows testing a single email or multiple sample domains.

Usage:
  # From project root
  python src/Test/test_mx.py test@example.com
  
  # Or run with sample domains
  python src/Test/test_mx.py
"""

import sys
import os
import json
from datetime import datetime
from pprint import pprint

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.engine.functions.mx import fetch_mx_records, MXCacher
from src.managers.log import Axe

# Initialize logger
logger = Axe()

def test_mx(email_or_domain):
    """
    Test MX record functionality for an email address or domain.
    
    Args:
        email_or_domain: Email address or domain to test
    """
    # Check if input is a domain or email
    if '@' in email_or_domain:
        domain = email_or_domain.split('@')[1].strip().lower()
        email = email_or_domain
        print(f"Testing MX records for email: {email} (domain: {domain})")
    else:
        domain = email_or_domain.strip().lower()
        email = f"test@{domain}"
        print(f"Testing MX records for domain: {domain}")
    
    # Create context dictionary that fetch_mx_records expects
    context = {
        "email": email,
        "trace_id": f"test-mx-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }
    
    # Create MX cacher instance for direct testing
    mx_cacher = MXCacher()
    
    # Test both methods
    print("\n=== Testing fetch_and_cache_mx (Basic MX Lookup) ===")
    basic_result = mx_cacher.fetch_and_cache_mx(domain)
    display_basic_mx_results(basic_result)
    
    print("\n\n=== Testing fetch_mx_records (Enhanced MX Lookup) ===")
    print("Fetching detailed MX records...")
    enhanced_result = fetch_mx_records(context)
    display_enhanced_mx_results(enhanced_result)

def display_basic_mx_results(result):
    """Display basic MX lookup results in a readable format."""
    print(f"\nDomain: {result.get('domain', 'N/A')}")
    print(f"Source: {result.get('source', 'direct')} (cache or dns_query)")
    print(f"Timestamp: {result.get('timestamp', 'N/A')}")
    
    if result.get("error"):
        print(f"Error: {result.get('error')}")
        return
        
    mx_records = result.get("mx_records", [])
    
    if not mx_records:
        print("No MX records found")
        return
    
    print(f"\nFound {len(mx_records)} MX records:")
    print("-" * 50)
    print(f"{'Preference':<10} {'Exchange':<40}")
    print("-" * 50)
    
    for mx in mx_records:
        print(f"{mx.get('preference', 'N/A'):<10} {mx.get('exchange', 'N/A'):<40}")
    
    print(f"\nExecution time: {result.get('duration_ms', 'N/A')} ms")

def display_enhanced_mx_results(result):
    """Display enhanced MX lookup results in a readable format."""
    print(f"\nValid: {result.get('valid', False)}")
    
    if not result.get('valid'):
        print(f"Error: {result.get('error', 'Unknown error')}")
        return
    
    records = result.get('records', [])
    
    print(f"\nHas MX Records: {result.get('has_mx', False)}")
    if result.get('used_fallback'):
        print("Note: Using A record fallback (RFC 5321 compliant)")
    
    # Display records
    if records:
        print(f"\nFound {len(records)} MX records:")
        print("-" * 50)
        print(f"{'Preference':<10} {'Exchange':<40} {'Fallback':<10}")
        print("-" * 50)
        
        for mx in records:
            fallback = "Yes" if mx.get('is_fallback', False) else "No"
            print(f"{mx.get('preference', 'N/A'):<10} {mx.get('exchange', 'N/A'):<40} {fallback:<10}")
    else:
        print("\nNo MX records found")
    
    # Display MX infrastructure
    infra = result.get('mx_infrastructure', {})
    if infra:
        print("\nMX Infrastructure:")
        print(f"  Load Balanced: {infra.get('load_balanced', False)}")
        print(f"  Has Failover: {infra.get('has_failover', False)}")
        
        primary = infra.get('primary')
        if primary:
            print(f"\n  Primary MX (Preference {primary.get('preference', 'N/A')}):")
            for server in primary.get('servers', []):
                print(f"    - {server}")
        
        backups = infra.get('backups', [])
        if backups:
            print("\n  Backup MX servers:")
            for backup in backups:
                print(f"    Preference {backup.get('preference', 'N/A')}:")
                for server in backup.get('servers', []):
                    print(f"    - {server}")
    
    # Display IP addresses
    ip_addresses = result.get('ip_addresses', {})
    if ip_addresses:
        print("\nIP Addresses:")
        
        ipv4 = ip_addresses.get('ipv4', [])
        if ipv4:
            print(f"\n  IPv4 ({len(ipv4)}):")
            for ip in ipv4[:5]:  # Limit to first 5
                print(f"    - {ip}")
            if len(ipv4) > 5:
                print(f"    - ... and {len(ipv4) - 5} more")
        
        ipv6 = ip_addresses.get('ipv6', [])
        if ipv6:
            print(f"\n  IPv6 ({len(ipv6)}):")
            for ip in ipv6[:3]:  # Limit to first 3
                print(f"    - {ip}")
            if len(ipv6) > 3:
                print(f"    - ... and {len(ipv6) - 3} more")
    
    # Display MX to IP mapping
    mx_ip_mapping = result.get('mx_ip_mapping', [])
    if mx_ip_mapping:
        print("\nMX to IP Mapping:")
        for mapping in mx_ip_mapping:
            mx_host = mapping.get('mx_host', 'N/A')
            ipv4 = mapping.get('ipv4', [])
            ipv6 = mapping.get('ipv6', [])
            
            print(f"\n  {mx_host}:")
            if ipv4:
                print(f"    IPv4: {', '.join(ipv4[:3])}" + (f", +{len(ipv4) - 3} more" if len(ipv4) > 3 else ""))
            if ipv6:
                print(f"    IPv6: {', '.join([ip[:24] + '...' for ip in ipv6[:2]])}" + 
                      (f", +{len(ipv6) - 2} more" if len(ipv6) > 2 else ""))
    
    # Display infrastructure info
    infra_info = result.get('infrastructure_info', {})
    if infra_info:
        print("\nInfrastructure Information:")
        
        providers = infra_info.get('providers', [])
        if providers:
            print(f"  Providers: {', '.join(providers)}")
        
        countries = infra_info.get('countries', [])
        if countries:
            print(f"  Countries: {', '.join(countries)}")
        
        ptr_records = infra_info.get('ptr_records', [])
        if ptr_records:
            print("\n  PTR Records:")
            for ptr in ptr_records:
                print(f"    {ptr.get('ip', 'N/A')}: {ptr.get('ptr', 'N/A')}")
    
    # Display email provider info
    email_provider = result.get('email_provider', {})
    if email_provider:
        print("\nEmail Provider:")
        print(f"  Provider: {email_provider.get('provider_name', 'Unknown')}")
        print(f"  Self-hosted: {email_provider.get('self_hosted', False)}")
    
    # Display execution time
    print(f"\nExecution time: {result.get('execution_time', 'N/A')} ms")

if __name__ == "__main__":
    # Check if email/domain is provided as command line argument
    if len(sys.argv) > 1:
        input_param = sys.argv[1]
        test_mx(input_param)
    else:
        # Use default test domains
        domains = [
            "gmail.com",
            "microsoft.com",
            "protonmail.com",
            "example.com",
            "nonexistentdomainthatshouldnotexist12345.com"  # Should fail
        ]
        
        print("No input provided. Testing with sample domains...\n")
        for domain in domains:
            print("="*70)
            print(f"TESTING DOMAIN: {domain}")
            print("="*70)
            test_mx(domain)
            print("\n\n")