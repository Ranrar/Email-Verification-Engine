"""
POP3 Validation Tester for Email Verification Engine
===================================================

This script tests the POP3 validation functionality of the Email Verification Engine.
It verifies POP3 server availability, capabilities, and security features.

Usage:
  # From project root
  python src/test/test_pop3.py test@example.com
  
  # Run with detailed statistics
  python src/test/test_pop3.py test@example.com --stats

  # Run with verbose output
  python src/test/test_pop3.py test@example.com --verbose

  # Run with sample domains
  python src/test/test_pop3.py

  # Test security assessment
  python src/test/test_pop3.py --security

  # Test cache functionality
  python src/test/test_pop3.py --test-cache test@example.com

  # Test rate limiting
  python src/test/test_pop3.py --test-rate-limits test@example.com

  # Test concurrent connections
  python src/test/test_pop3.py --test-concurrent test@example.com

  # Test error handling
  python src/test/test_pop3.py --test-errors

  # Test MX record integration
  python src/test/test_pop3.py --test-mx

  # Test timeout handling
  python src/test/test_pop3.py --test-timeouts

  # Test all cache mechanisms
  python src/test/test_pop3.py --test-all-caches
"""

import sys
import os
import json
import time
import threading
import uuid
from datetime import datetime
from pprint import pprint
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.engine.functions.pop3 import POP3Verifier, POP3Result, POP3Record, pop3_check
from src.managers.log import get_logger
from src.managers.cache import cache_manager, CacheKeys
from src.managers.rate_limit import RateLimitManager
from src.helpers.dbh import sync_db
from src.helpers.tracer import ensure_trace_id

# Initialize logger
logger = get_logger()

# Get rate limit manager instance
rate_limit_manager = RateLimitManager()

def create_test_trace_record(trace_id: str, email: str, domain: str):
    """Create a test record in email_validation_records for foreign key constraint"""
    try:
        # Check if record already exists
        existing = sync_db.fetchrow("SELECT trace_id FROM email_validation_records WHERE trace_id = $1", trace_id)
        if existing:
            logger.debug(f"Trace record {trace_id} already exists")
            return
            
        # Insert minimal test record
        sync_db.execute("""
            INSERT INTO email_validation_records 
            (trace_id, email, domain, test_mode, created_at)
            VALUES ($1, $2, $3, true, NOW())
            ON CONFLICT (trace_id) DO NOTHING
        """, trace_id, email, domain)
        
        logger.debug(f"Created test trace record: {trace_id}")
        
    except Exception as e:
        logger.warning(f"Could not create test trace record: {e}")

def test_pop3(email, show_stats=False, verbose=False):
    """
    Test POP3 validation for an email address.
    
    Args:
        email: Email address to validate
        show_stats: Whether to show statistics after validation
        verbose: Whether to show verbose output
    """
    print(f"\nTesting POP3 validation for: {email}")
    
    # Generate proper UUID trace ID
    trace_id = str(uuid.uuid4())
    print(f"Using trace ID: {trace_id}")
    
    # Extract domain from email
    domain = email.split('@')[1] if '@' in email else email
    
    # Create test trace record for foreign key constraint
    create_test_trace_record(trace_id, email, domain)
    
    # Show domain statistics before validation if requested
    if show_stats:
        print("\n📊 DOMAIN POP3 STATISTICS (BEFORE):")
        display_pop3_stats(domain)
        
    # Start timer
    start_time = time.time()
    print("Starting POP3 validation...")
    
    # Initialize POP3 verifier
    try:
        pop3_verifier = POP3Verifier()
    except Exception as e:
        print(f"❌ Error initializing POP3 verifier: {e}")
        return None
    
    try:
        # Run POP3 validation
        result = pop3_verifier.check_pop3(domain, trace_id=trace_id)
        
        # Validate result is POP3Result object
        if not isinstance(result, POP3Result):
            print(f"❌ Unexpected result type: {type(result)}")
            return None
        
        # Print results
        display_pop3_results(result, verbose)
        
        # Show statistics after validation if requested
        if show_stats:
            print("\n📊 DOMAIN POP3 STATISTICS (AFTER):")
            display_pop3_stats(domain)
            
        return result
        
    except Exception as e:
        print(f"\n❌ Error running POP3 validation: {e}")
        logger.error(f"POP3 validation error: {e}")
        return None

def display_pop3_results(result: POP3Result, verbose=False):
    """Display POP3 validation results in a readable format"""
    print(f"\n{'='*70}")
    print(f" 📬 POP3 VALIDATION RESULTS")
    print(f"{'='*70}")
    
    # Basic information
    print(f"Domain: {result.domain}")
    print(f"Trace ID: {result.trace_id}")
    print(f"Duration: {result.duration_ms:.2f}ms")
    
    # POP3 availability
    if result.has_pop3:
        print(f"✅ POP3 Status: Available")
        print(f"🔒 Security Level: {result.security_level}")
        print(f"📊 Servers Found: {len(result.pop3_servers)}")
    else:
        print(f"❌ POP3 Status: Not Available")
        if result.error:
            print(f"❌ Error: {result.error}")
    
    # Security features
    if result.has_pop3:
        print(f"\n🔐 Security Features:")
        print(f"  SSL/TLS Support: {'✅ Yes' if result.supports_ssl else '❌ No'}")
        print(f"  STARTTLS Support: {'✅ Yes' if result.supports_starttls else '❌ No'}")
        print(f"  OAuth Support: {'✅ Yes' if result.supports_oauth else '❌ No'}")
    
    # Server details
    if result.pop3_servers:
        print(f"\n📡 POP3 Servers ({len(result.pop3_servers)}):")
        for i, server in enumerate(result.pop3_servers, 1):
            print(f"  {i}. {server.host}:{server.port} ({server.protocol})")
            print(f"     Secure: {'✅ Yes' if server.secure_connection else '❌ No'}")
            
            if verbose:
                print(f"     Banner: {server.banner[:60]}{'...' if len(server.banner) > 60 else ''}")
                print(f"     Capabilities: {len(server.capabilities)} found")
                if server.capabilities:
                    caps_display = ', '.join(server.capabilities[:5])
                    if len(server.capabilities) > 5:
                        caps_display += f" (+{len(server.capabilities) - 5} more)"
                    print(f"     - {caps_display}")
                
                print(f"     Features:")
                print(f"       STARTTLS: {'✅' if server.supports_starttls else '❌'}")
                print(f"       USER/PASS: {'✅' if server.supports_user_pass else '❌'}")
                print(f"       APOP: {'✅' if server.supports_apop else '❌'}")
                print(f"       OAuth: {'✅' if server.supports_oauth else '❌'}")
                print(f"       TOP: {'✅' if server.supports_top else '❌'}")
                print(f"       UIDL: {'✅' if server.supports_uidl else '❌'}")
            print()
    
    # Servers checked
    if result.servers_checked:
        print(f"🔍 Servers Checked: {', '.join(result.servers_checked)}")
    
    # Recommendations
    if result.recommendations:
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(result.recommendations, 1):
            print(f"  {i}. {rec}")

def display_pop3_stats(domain):
    """Display POP3 statistics for a domain from the database"""
    try:
        # Get recent POP3 validation statistics
        stats = sync_db.fetchrow("""
            SELECT has_pop3, servers_found, security_level, supports_ssl, 
                   supports_starttls, supports_oauth, processing_time_ms,
                   created_at
            FROM pop3_validation_statistics 
            WHERE domain = $1 
            ORDER BY created_at DESC 
            LIMIT 1
        """, domain)
        
        if stats:
            print(f"  Domain: {domain}")
            print(f"  Last check: {stats['created_at']}")
            print(f"  Has POP3: {'✅ Yes' if stats['has_pop3'] else '❌ No'}")
            if stats['has_pop3']:
                print(f"  Servers found: {stats['servers_found']}")
                print(f"  Security level: {stats['security_level']}")
                print(f"  SSL support: {'✅' if stats['supports_ssl'] else '❌'}")
                print(f"  STARTTLS support: {'✅' if stats['supports_starttls'] else '❌'}")
                print(f"  OAuth support: {'✅' if stats['supports_oauth'] else '❌'}")
            print(f"  Processing time: {stats['processing_time_ms']:.2f}ms")
        else:
            print(f"  No previous POP3 statistics found for {domain}")
            
    except Exception as e:
        print(f"  ❌ Error retrieving statistics: {e}")

def test_pop3_security():
    """Test POP3 security assessment with different server configurations"""
    print("\n" + "="*70)
    print(" 🔒 TESTING POP3 SECURITY ASSESSMENT")
    print("="*70)
    
    # Test domains with different security levels
    test_domains = [
        "gmail.com",       # Should be high security
        "outlook.com",     # Should be high security  
        "yahoo.com",       # Should be medium/high security
        "icloud.com",      # Should be high security
        "aol.com",         # Should be medium security
        "mail.com",        # German email service - should have good security
        "gmx.com",         # German GMX provider - should have good security
        "example.com",     # May not have POP3
        "nonexistent12345.invalid"  # Should fail
    ]
    
    print("Testing security assessment on various email domains...")
    results = {}
    
    for i, domain in enumerate(test_domains, 1):
        print(f"\n({i}/{len(test_domains)}) Testing security for: {domain}")
        
        try:
            pop3_verifier = POP3Verifier()
            result = pop3_verifier.check_pop3(domain)
            
            if result.has_pop3:
                security = result.security_level
                server_count = len(result.pop3_servers)
                print(f"✅ POP3 available - Security: {security}, Servers: {server_count}")
                results[domain] = {
                    'security': security,
                    'available': True,
                    'servers': server_count,
                    'ssl': result.supports_ssl,
                    'starttls': result.supports_starttls,
                    'oauth': result.supports_oauth
                }
            else:
                error = result.error if result.error else "No POP3 servers found"
                print(f"❌ POP3 not available - {error}")
                results[domain] = {
                    'security': 'N/A',
                    'available': False,
                    'error': error
                }
        except Exception as e:
            print(f"❌ Error testing {domain}: {e}")
            results[domain] = {
                'security': 'ERROR',
                'available': False,
                'error': str(e)
            }
        
        # Small delay between tests
        time.sleep(1)
    
    # Print summary table
    print("\n" + "="*80)
    print(" 📊 SECURITY ASSESSMENT SUMMARY")
    print("="*80)
    print(f"{'Domain':<25} {'Available':<10} {'Security':<10} {'SSL':<5} {'STARTTLS':<9} {'OAuth':<6}")
    print("-"*80)
    
    for domain, info in results.items():
        available = "✅ Yes" if info['available'] else "❌ No"
        security = info['security']
        ssl = "✅" if info.get('ssl') else "❌" if info['available'] else "-"
        starttls = "✅" if info.get('starttls') else "❌" if info['available'] else "-"
        oauth = "✅" if info.get('oauth') else "❌" if info['available'] else "-"
        
        print(f"{domain:<25} {available:<10} {security:<10} {ssl:<5} {starttls:<9} {oauth:<6}")
        
    print("-"*80)

def test_pop3_cache(email):
    """Test the POP3 cache functionality"""
    logger.info("="*70)
    logger.info("🗄️ TESTING POP3 CACHE")
    logger.info("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    logger.info(f"Testing cache for domain: {domain}")
    
    # Initialize POP3 verifier to get cache TTL from rate limit manager
    logger.debug("Initializing POP3 verifier")
    pop3_verifier = POP3Verifier()
    cache_ttl = pop3_verifier.rate_limit_manager.get_pop3_capabilities_cache_ttl()
    
    # Clear any existing domain-level cache
    domain_cache_key = CacheKeys.pop3(domain)
    logger.debug(f"Domain cache key: {domain_cache_key}")
    try:
        cache_manager.delete(domain_cache_key)
        logger.info("🧹 Cleared existing domain cache")
    except Exception as e:
        logger.warning(f"Error clearing cache: {e}")
    
    # Display cache TTL
    logger.info(f"POP3 cache TTL from database: {cache_ttl} seconds")
    
    # Run first check and measure time
    logger.info("\n1️⃣ First check (should miss cache):")
    start_time = time.time()
    logger.debug(f"Starting first POP3 check for {domain}")
    result1 = pop3_verifier.check_pop3(domain)
    duration1 = (time.time() - start_time) * 1000
    
    logger.info(f"Result: {'✅ Available' if result1.has_pop3 else '❌ Not available'}")
    logger.info(f"Duration: {duration1:.2f}ms")
    logger.info(f"Security: {result1.security_level}")
    
    # Log detailed results
    logger.debug(f"Found {len(result1.pop3_servers)} POP3 server records")
    for idx, record in enumerate(result1.pop3_servers):
        logger.debug(f"Record {idx+1}: {record.host}:{record.port} - Success: {record.success}")
        if record.success:
            logger.debug(f"  - Banner: {record.banner[:50]}...")
            logger.debug(f"  - Capabilities: {', '.join(record.capabilities[:5])}{'...' if len(record.capabilities) > 5 else ''}")
    
    if result1.has_pop3 and result1.pop3_servers:
        # Check for server capabilities cache
        first_server = result1.pop3_servers[0]
        server_id = f"{first_server.host}:{first_server.port}"
        capabilities_key = CacheKeys.pop3_capabilities(server_id)
        
        logger.info(f"\nChecking server-level caches for {server_id}:")
        logger.debug(f"Capabilities cache key: {capabilities_key}")
        
        capabilities_cache = cache_manager.get(capabilities_key)
        
        has_capabilities_cache = capabilities_cache is not None
        
        logger.info(f"Capabilities cache: {'✅ Found' if has_capabilities_cache else '❌ Not found'}")
        
        if has_capabilities_cache:
            logger.debug(f"Cached capabilities: {capabilities_cache}")
    
    # Run second check and measure time
    logger.info("\n2️⃣ Second check (should hit cache):")
    start_time = time.time()
    logger.debug(f"Starting second POP3 check for {domain}")
    result2 = pop3_verifier.check_pop3(domain)
    duration2 = (time.time() - start_time) * 1000
    
    logger.info(f"Result: {'✅ Available' if result2.has_pop3 else '❌ Not available'}")
    logger.info(f"Duration: {duration2:.2f}ms")
    logger.info(f"Security: {result2.security_level}")
    
    # Compare times
    time_diff = duration1 - duration2
    if time_diff > 50:  # At least 50ms improvement expected for cache hit
        logger.info(f"\n🎉 Cache hit success! Second check was {time_diff:.2f}ms faster")
        logger.info(f"Speed improvement: {(time_diff / duration1 * 100):.1f}%")
    elif duration2 < 10:  # Very fast response suggests cache hit
        logger.info(f"\n🎉 Cache appears to be working (very fast response: {duration2:.2f}ms)")
    else:
        logger.warning(f"\n⚠️  Cache may not be working properly (similar timing)")
        logger.debug(f"First check: {duration1:.2f}ms, Second check: {duration2:.2f}ms")
    
    # Check domain cache directly
    try:
        cached_data = cache_manager.get(domain_cache_key)
        if cached_data:
            logger.info("\n✅ Found entry in domain cache")
            cache_type = type(cached_data).__name__
            logger.info(f"Cache entry type: {cache_type}")
            logger.info(f"Cache will expire in: {cache_ttl} seconds (from database)")
            logger.debug(f"Cache contents (partial): {str(cached_data)[:200]}...")
        else:
            logger.warning("\n❌ No domain cache entry found")
    except Exception as e:
        logger.error(f"\n❌ Error checking cache: {e}", exc_info=True)

def test_rate_limits(email):
    """Test POP3 rate limiting functionality"""
    print("\n" + "="*70)
    print(" 🚦 TESTING POP3 RATE LIMITS")
    print("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    print(f"Testing rate limits for domain: {domain}")
    
    # Get rate limits from database
    pop3_verifier = POP3Verifier()
    connection_limit = pop3_verifier.max_connections_per_minute
    concurrent_limit = pop3_verifier.max_concurrent_sessions
    timeout = pop3_verifier.connection_timeout
    
    print(f"Database rate limit settings:")
    print(f"Connection limit: {connection_limit}/min (category: pop3, name: max_connections_per_minute)")
    print(f"Concurrent sessions: {concurrent_limit} (category: pop3, name: max_concurrent_sessions)")
    print(f"Connection timeout: {timeout}s (category: pop3, name: timeout_connect)")
    
    # Reset usage counters for clean test
    try:
        # Clear rate limit usage counter from cache
        cache_key = f"rate_limit:pop3:max_connections_per_minute:{domain}"
        cache_manager.delete(cache_key)
        print("🧹 Cleared existing rate limit counters")
    except:
        pass
    
    # Rapid succession test
    num_tests = min(connection_limit + 2, 10)  # Test enough to potentially hit limit, but cap at 10
    print(f"\n🔄 Testing {num_tests} rapid succession calls to approach limit...")
    results = []
    
    for i in range(num_tests):
        print(f"Call {i+1}/{num_tests}...")
        start_time = time.time()
        result = pop3_verifier.check_pop3(domain)
        duration = (time.time() - start_time) * 1000
        
        results.append({
            'call': i+1,
            'duration': duration,
            'success': result.has_pop3 if not result.error else False,
            'error': result.error
        })
        
        print(f"  Duration: {duration:.2f}ms")
        if result.error and "rate limit" in result.error.lower():
            print(f"  ⚠️ Rate limited: {result.error}")
        elif result.error:
            print(f"  ❌ Error: {result.error}")
        else:
            print(f"  ✅ Success")
        
        # Small delay to see rate counter increment
        time.sleep(0.5)
    
    # Summary
    print("\n📊 Rate Limit Test Summary:")
    for result in results:
        status = "Rate Limited" if result['error'] and "rate limit" in result['error'].lower() else \
                "Error" if result['error'] else "Success"
        print(f"  Call {result['call']}: {result['duration']:.2f}ms - {status}")

def test_concurrent_connections(email, num_threads=8):
    """Test concurrent POP3 connections for rate limiting"""
    print("\n" + "="*70)
    print(" 🔄 TESTING CONCURRENT CONNECTIONS")
    print("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    print(f"Testing concurrent connections for domain: {domain}")
    
    # Get rate limits from database
    pop3_verifier = POP3Verifier()
    concurrent_limit = pop3_verifier.max_concurrent_sessions
    
    print(f"Database concurrency settings:")
    print(f"Max concurrent sessions: {concurrent_limit} (category: pop3, name: max_concurrent_sessions)")
    
    # Reset usage counters for clean test
    try:
        # Clear rate limit usage counter from cache
        cache_key = f"rate_limit:pop3:max_connections_per_minute:{domain}"
        cache_manager.delete(cache_key)
        print("🧹 Cleared existing rate limit counters")
    except Exception as e:
        print(f"⚠️ Unable to clear cache: {e}")
    
    # Adjust thread count to be more than limit to test limiting
    num_threads = max(num_threads, concurrent_limit + 2)
    print(f"Starting {num_threads} concurrent connections (above limit of {concurrent_limit})...")
    
    results = []
    futures = []
    
    # Function for each thread to execute
    def check_domain(thread_id):
        try:
            print(f"Thread {thread_id}: Starting connection to {domain}...")
            start_time = time.time()
            result = pop3_verifier.check_pop3(domain)
            duration = (time.time() - start_time) * 1000
            
            print(f"Thread {thread_id}: Completed in {duration:.2f}ms")
            
            return {
                'thread': thread_id,
                'duration': duration,
                'success': result.has_pop3 if not result.error else False,
                'error': result.error
            }
        except Exception as e:
            print(f"Thread {thread_id}: Error - {e}")
            return {
                'thread': thread_id,
                'duration': 0,
                'success': False,
                'error': str(e)
            }
    
    # Use ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit tasks
        for i in range(num_threads):
            futures.append(executor.submit(check_domain, i+1))
        
        # Collect results as they complete
        for future in as_completed(futures):
            results.append(future.result())
    
    # Sort results by thread ID for display
    results.sort(key=lambda x: x['thread'])
    
    # Print summary
    print("\n📊 Concurrent Connection Test Summary:")
    success_count = sum(1 for r in results if r['success'])
    rate_limited = sum(1 for r in results if "rate limit" in r.get('error', '').lower())
    other_errors = sum(1 for r in results if r.get('error') and not ("rate limit" in r.get('error', '').lower()))
    
    print(f"Total threads: {num_threads}")
    print(f"Successful connections: {success_count}")
    print(f"Rate/concurrency limited: {rate_limited}")
    print(f"Other errors: {other_errors}")
    
    # Display individual thread results
    print("\nDetailed Thread Results:")
    print(f"{'Thread':<8} {'Duration (ms)':<15} {'Status':<15} {'Error'}")
    print("-"*70)
    
    for result in results:
        thread_id = result['thread']
        duration = f"{result['duration']:.2f}" if result['duration'] else "N/A"
        
        if result['success']:
            status = "✅ Success"
            error = ""
        elif "rate limit" in result.get('error', '').lower():
            status = "⚠️ Rate Limited"
            error = result.get('error', '')
        else:
            status = "❌ Error"
            error = result.get('error', '')
            
        print(f"{thread_id:<8} {duration:<15} {status:<15} {error[:40]}")

def test_error_handling():
    """Test POP3 error handling with various problematic domains"""
    logger.info("="*70)
    logger.info("🚨 TESTING ERROR HANDLING")
    logger.info("="*70)
    
    # Test cases with expected errors
    test_cases = [
        {
            'domain': 'nonexistent12345.invalid',
            'expected': 'DNS resolution error',
            'description': 'Non-existent domain'
        },
        {
            'domain': 'localhost',
            'expected': 'Connection refused',
            'description': 'Connection refused'
        },
        {
            'domain': '192.0.2.1',  # RFC5737 test IP
            'expected': 'timeout|refused',
            'description': 'Invalid IP address'
        },
        {
            'domain': '',
            'expected': 'Invalid domain',
            'description': 'Empty domain'
        }
    ]
    
    # Create an instance of POP3Verifier for tests
    try:
        logger.debug("Creating POP3Verifier for error handling tests")
        pop3_verifier = POP3Verifier()
        logger.info("\n✅ Created POP3Verifier with valid port configuration")
        
        # Display the loaded POP3 ports
        if hasattr(pop3_verifier, "pop3_ports"):
            logger.info(f"Loaded {len(pop3_verifier.pop3_ports)} POP3 ports:")
            for port_config in pop3_verifier.pop3_ports:
                logger.info(f"  - Port {port_config['port']}: {port_config['protocol']}")
    except Exception as e:
        logger.error(f"\n❌ Could not create POP3Verifier: {e}", exc_info=True)
        logger.warning("Skipping remaining error handling tests")
        return
    
    # Show error handling rate limits from database
    logger.info("\nPOP3 error handling configuration (from database):")
    logger.info(f"Connect timeout: {pop3_verifier.connection_timeout}s")
    logger.info(f"Read timeout: {pop3_verifier.read_timeout}s")
    logger.info(f"Max connections per minute: {pop3_verifier.max_connections_per_minute}")
    
    # Test each error case
    for test_case in test_cases:
        domain = test_case['domain']
        expected = test_case['expected']
        description = test_case['description']
        
        logger.info(f"\n🧪 Testing: {description} ({domain})")
        logger.debug(f"Expected error pattern: {expected}")
        
        # Attempt POP3 check
        try:
            logger.debug(f"Performing POP3 check for {domain}")
            result = pop3_verifier.check_pop3(domain)
            
            # Check result
            if result.has_pop3:
                logger.warning(f"❌ Unexpected success for {domain}")
            elif result.error:
                error_msg = result.error.lower()
                logger.info(f"✅ Got expected error: {result.error}")
                
                # Verify error type matches expectation
                if any(pattern in error_msg for pattern in expected.split('|')):
                    logger.info(f"✅ Error type matches expectation")
                else:
                    logger.warning(f"⚠️ Error type doesn't match expectation: got '{result.error}', expected pattern '{expected}'")
            else:
                logger.warning(f"❌ No error reported for problematic domain {domain}")
                
        except Exception as e:
            logger.info(f"✅ Exception caught as expected: {e}")

def test_mx_record_integration():
    """Test MX record integration with POP3 verification"""
    print("\n" + "="*70)
    print(" 🔍 TESTING MX RECORD INTEGRATION WITH POP3")
    print("="*70)
    
    logger.info("Testing how POP3 verification uses MX records")
    
    # Initialize POP3 verifier
    try:
        pop3_verifier = POP3Verifier()
        print("✅ Successfully initialized POP3 verifier")
    except Exception as e:
        print(f"❌ Error initializing POP3 verifier: {e}")
        return
    
    # Define test cases with both domains and email addresses
    test_cases = [
        {
            "input": "gmail.com",
            "description": "Domain only - major email provider",
            "expect_mx": True,
            "input_type": "domain"
        },
        {
            "input": "user@gmail.com",
            "description": "Email address - major provider",
            "expect_mx": True,
            "input_type": "email"
        },
        {
            "input": "mail.com",
            "description": "German email service domain",
            "expect_mx": True,
            "input_type": "domain"
        },
        {
            "input": "user@gmx.com",
            "description": "German GMX provider email",
            "expect_mx": True,
            "input_type": "email"
        },
        {
            "input": "example.com",
            "description": "Domain that may not have MX records",
            "expect_mx": False,
            "input_type": "domain"
        },
        {
            "input": "nonexistent12345.invalid",
            "description": "Non-existent domain",
            "expect_mx": False,
            "input_type": "domain"
        }
    ]
    
    for test in test_cases:
        input_value = test["input"]
        description = test["description"]
        expect_mx = test["expect_mx"]
        input_type = test["input_type"]
        
        print(f"\n🧪 Testing: {input_value} - {description}")
        print(f"  Input type: {input_type.upper()}")
        print(f"  Expecting MX records: {'Yes' if expect_mx else 'No'}")
        
        # Perform POP3 check
        try:
            result = pop3_verifier.check_pop3(input_value)
            print(f"  POP3 check result: {'✅ Success' if result.has_pop3 else '❌ Failed'}")
            
            # Check which hosts were actually checked
            hosts_checked = set(result.servers_checked)
            
            # Extract domain properly regardless of input type
            domain = input_value.split('@')[1] if '@' in input_value else input_value
            
            print(f"\n  Hosts checked ({len(hosts_checked)}):")
            for host in hosts_checked:
                if domain == host:
                    print(f"    • {host} (domain itself)")
                elif any(host == f"{pattern}.{domain}" for pattern in ["mail", "pop", "pop3", "webmail", "exchange"]):
                    print(f"    • {host} (hardcoded pattern)")
                else:
                    print(f"    • {host} (likely from MX)")
                    
        except Exception as e:
            print(f"  ❌ Error during POP3 check: {e}")

def test_timeout_handling():
    """Test the timeout handling in POP3 connections"""
    print("\n" + "="*70)
    print(" ⏱️ TESTING POP3 TIMEOUT HANDLING")
    print("="*70)
    
    logger.info("Testing POP3 connection timeout handling")
    
    # Initialize POP3 verifier
    try:
        pop3_verifier = POP3Verifier()
        print(f"✅ Successfully initialized POP3 verifier")
        print(f"   Connect timeout: {pop3_verifier.connection_timeout}s")
        print(f"   Read timeout: {pop3_verifier.read_timeout}s")
    except Exception as e:
        print(f"❌ Error initializing POP3 verifier: {e}")
        return
    
    # Test cases for timeout behavior
    test_cases = [
        {
            "host": "example.com",  # Likely doesn't have POP3
            "port": 110,
            "use_ssl": False,
            "timeout": 3.0,  # Short timeout to speed up test
            "description": "Standard connection with short timeout"
        },
        {
            "host": "10.255.255.1",  # Reserved IP that should timeout
            "port": 110,
            "use_ssl": False,
            "timeout": 2.0,
            "description": "Network timeout test with unreachable IP"
        },
        {
            "host": "gmail.com",  # Valid host, wrong port
            "port": 1,
            "use_ssl": False,
            "timeout": 2.0,
            "description": "Connection refused test"
        }
    ]
    
    # Track start and end times
    for test in test_cases:
        host = test["host"]
        port = test["port"]
        use_ssl = test["use_ssl"]
        timeout = test["timeout"]
        description = test["description"]
        
        print(f"\n🧪 Testing: {description}")
        print(f"   Connection to {host}:{port} (SSL: {use_ssl}) with {timeout}s timeout")
        
        start_time = time.time()
        print(f"   Starting at: {start_time:.2f}")
        
        try:
            pop3_record = pop3_verifier._connect_to_pop3_server(host, port, use_ssl, timeout)
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"   Finished at: {end_time:.2f}")
            print(f"   Duration: {duration:.2f}s (timeout was set to {timeout}s)")
            
            if pop3_record.success:
                print(f"   ✅ Connection succeeded (unexpected for timeout test)")
                print(f"   Banner: {pop3_record.banner[:30]}...")
                print(f"   Capabilities: {len(pop3_record.capabilities)} found")
            else:
                print(f"   ❌ Connection failed as expected")
                print(f"   Error: {pop3_record.error}")
                
            # Check if timeout was respected (allow small buffer for processing)
            if not pop3_record.success and "timeout" in pop3_record.error.lower():
                if duration <= timeout + 0.5:
                    print(f"   ✅ Timeout respected: {duration:.2f}s <= {timeout + 0.5:.2f}s")
                else:
                    print(f"   ❌ Timeout NOT respected: {duration:.2f}s > {timeout + 0.5:.2f}s")
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            print(f"   ❌ Exception: {e}")
            print(f"   Duration: {duration:.2f}s")

def test_cache_mechanism():
    """Test all cache mechanisms used in POP3 verification"""
    print("\n" + "="*70)
    print(" 🗂️ TESTING COMPREHENSIVE POP3 CACHE MECHANISM")
    print("="*70)
    
    # Initialize POP3 verifier
    try:
        pop3_verifier = POP3Verifier()
        cache_ttl = pop3_verifier.rate_limit_manager.get_pop3_capabilities_cache_ttl()
        print("✅ Successfully initialized POP3 verifier")
        print(f"   Cache TTL: {cache_ttl}s")
    except Exception as e:
        print(f"❌ Error initializing POP3 verifier: {e}")
        return
    
    # Choose a test domain
    domain = "gmail.com"  # Should have POP3
    print(f"Testing with domain: {domain}")
    
    # Clear all caches related to this domain
    domain_cache_key = CacheKeys.pop3(domain)
    cache_manager.delete(domain_cache_key)
    print(f"✓ Cleared domain cache: {domain_cache_key}")
    
    # First check creates all caches
    print("\n1️⃣ First check - should miss all caches:")
    start_time = time.time()
    result1 = pop3_verifier.check_pop3(domain)
    duration1 = (time.time() - start_time) * 1000
    
    print(f"   Duration: {duration1:.2f}ms")
    print(f"   Success: {'✅ Yes' if result1.has_pop3 else '❌ No'}")
    print(f"   Servers found: {len(result1.pop3_servers)}")
    
    # Find all servers to check caches for
    print("\n📊 Checking caches for each server:")
    
    # Check domain-level cache
    domain_cache = cache_manager.get(domain_cache_key)
    print(f"\n📂 Domain cache ({domain_cache_key}):")
    print(f"   {'✅ Found' if domain_cache else '❌ Not found'}")
    
    # Check server-level caches if available
    if result1.pop3_servers:
        for server in result1.pop3_servers:
            server_id = f"{server.host}:{server.port}"
            capabilities_key = CacheKeys.pop3_capabilities(server_id)
            
            capabilities_cache = cache_manager.get(capabilities_key)
            
            print(f"\n📡 Server cache for {server_id}:")
            print(f"   Capabilities: {'✅ Found' if capabilities_cache else '❌ Not found'}")
    
    # Second check should hit caches
    print("\n2️⃣ Second check - should hit caches:")
    start_time = time.time()
    result2 = pop3_verifier.check_pop3(domain)
    duration2 = (time.time() - start_time) * 1000
    
    print(f"   Duration: {duration2:.2f}ms")
    print(f"   Success: {'✅ Yes' if result2.has_pop3 else '❌ No'}")
    print(f"   Servers found: {len(result2.pop3_servers)}")
    
    # Compare performance
    if duration1 > 0 and duration2 > 0:
        speedup = (duration1 - duration2) / duration1 * 100
        print(f"\n🚀 Performance comparison:")
        print(f"   First check: {duration1:.2f}ms")
        print(f"   Second check: {duration2:.2f}ms")
        print(f"   Speedup: {speedup:.1f}%")
        
        if speedup > 30:
            print("✅ Cache appears to be working well!")
        elif speedup > 10:
            print("⚠️ Cache provides some benefit")
        else:
            print("⚠️ Cache may not be working optimally")

def main():
    """Main function to parse command line args and run tests"""
    import argparse
    
    # Check command line arguments for test options
    show_stats = "--stats" in sys.argv
    verbose = "--verbose" in sys.argv
    test_security = "--security" in sys.argv
    test_cache = "--test-cache" in sys.argv
    test_rate_limits_flag = "--test-rate-limits" in sys.argv
    test_concurrent = "--test-concurrent" in sys.argv
    test_errors = "--test-errors" in sys.argv
    test_mx = "--test-mx" in sys.argv
    test_timeouts = "--test-timeouts" in sys.argv
    test_all_caches = "--test-all-caches" in sys.argv
    
    # If testing security assessment
    if test_security:
        test_pop3_security()
        return
    
    # If testing cache mechanism
    if test_all_caches:
        test_cache_mechanism()
        return
    
    # If testing timeouts
    if test_timeouts:
        test_timeout_handling()
        return
    
    # If testing MX integration
    if test_mx:
        test_mx_record_integration()
        return
    
    # If testing cache functionality
    if test_cache:
        email_arg = None
        for arg in sys.argv[1:]:
            if not arg.startswith('-') and '@' in arg:
                email_arg = arg
                break
                
        if email_arg:
            test_pop3_cache(email_arg)
        else:
            test_pop3_cache("test@gmail.com")  # Default domain
        return
    
    # If testing rate limits
    if test_rate_limits_flag:
        email_arg = None
        for arg in sys.argv[1:]:
            if not arg.startswith('-') and '@' in arg:
                email_arg = arg
                break
                
        if email_arg:
            test_rate_limits(email_arg)
        else:
            test_rate_limits("test@gmail.com")  # Default domain
        return
    
    # If testing concurrent connections
    if test_concurrent:
        email_arg = None
        for arg in sys.argv[1:]:
            if not arg.startswith('-') and '@' in arg:
                email_arg = arg
                break
                
        if email_arg:
            test_concurrent_connections(email_arg)
        else:
            test_concurrent_connections("test@gmail.com")  # Default domain
        return
    
    # If testing error handling
    if test_errors:
        test_error_handling()
        return
    
    # Check if email is provided as command line argument
    email_arg = None
    for arg in sys.argv[1:]:
        if not arg.startswith('-') and '@' in arg:
            email_arg = arg
            break
    
    if email_arg:
        # Test the specified email
        test_pop3(email_arg, show_stats, verbose)
    else:
        # Use sample emails
        sample_emails = [
            # Valid popular email domains - these should work
            "test@gmail.com",
            "info@outlook.com",
            "test@yahoo.com",
            
            # Valid but different providers
            "test@icloud.com",
            "test@aol.com",
            
            # European email providers
            "test@mail.com",        # German-based email service
            "test@gmx.com",         # German email provider (GMX)
            
            # Non-existent domain - this should fail with DNS error
            "test@nonexistentdomain123456789.com",
            
            # Example domain - this should be handled appropriately
            "test@example.com"
        ]
        
        print(f"\nAvailable test options:")
        print(f"  --stats             Show domain statistics from database")
        print(f"  --verbose           Show detailed technical information")
        print(f"  --security          Test security assessment on multiple domains")
        print(f"  --test-cache        Test cache functionality")
        print(f"  --test-rate-limits  Test rate limiting")
        print(f"  --test-concurrent   Test concurrent connections")
        print(f"  --test-errors       Test error handling")
        print(f"  --test-mx           Test MX record integration with POP3")
        print(f"  --test-timeouts     Test connection timeout handling")
        print(f"  --test-all-caches   Test all types of POP3 caches")
        
        print(f"\n🧪 Running comprehensive test on {len(sample_emails)} domains...\n")
        
        for i, email in enumerate(sample_emails, 1):
            print(f"\n{'#'*70}")
            print(f"TEST {i}/{len(sample_emails)}: {email}")
            print(f"{'#'*70}")
            try:
                result = test_pop3(email, show_stats, verbose)
                if result:
                    print(f"✅ Test completed successfully")
                else:
                    print(f"❌ Test failed or returned no result")
            except Exception as e:
                print(f"❌ Error testing {email}: {e}")
                logger.error(f"Test error for {email}", exc_info=True)
            
            # Pause between tests
            if i < len(sample_emails):
                time.sleep(2)

if __name__ == "__main__":
    main()