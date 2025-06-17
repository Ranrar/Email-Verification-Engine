"""
IMAP Validation Tester for Email Verification Engine
===================================================

This script tests the IMAP validation functionality of the Email Verification Engine.
It verifies IMAP server availability, capabilities, and security features.

Usage:
  # From project root
  python src/test/test_imap.py test@example.com
  
  # Run with detailed statistics
  python src/test/test_imap.py test@example.com --stats

  # Run with verbose output
  python src/test/test_imap.py test@example.com --verbose

  # Run with sample domains
  python src/test/test_imap.py

  # Test security assessment
  python src/test/test_imap.py --security

  # Test cache functionality
  python src/test/test_imap.py --test-cache test@example.com

  # Test rate limiting
  python src/test/test_imap.py --test-rate-limits test@example.com

  # Test concurrent connections
  python src/test/test_imap.py --test-concurrent test@example.com

  # Test error handling
  python src/test/test_imap.py --test-errors
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
from src.engine.functions.imap import IMAPVerifier, IMAPResult, IMAPRecord
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
        # Check if record exists
        existing = sync_db.fetchval("""
            SELECT trace_id FROM email_validation_records WHERE trace_id = $1
        """, trace_id)
        
        if not existing:
            # Create minimal record for testing
            sync_db.execute("""
                INSERT INTO email_validation_records 
                (trace_id, email, domain, timestamp) 
                VALUES ($1, $2, $3, NOW())
            """, trace_id, email, domain)
            print(f"Created test validation record for trace: {trace_id}")
    except Exception as e:
        print(f"Could not create test trace record: {e}")

def test_imap(email, show_stats=False, verbose=False):
    """
    Test IMAP validation for an email address.
    
    Args:
        email: Email address to validate
        show_stats: Whether to show statistics after validation
        verbose: Whether to show verbose output
    """
    print(f"\nTesting IMAP validation for: {email}")
    
    # Generate proper UUID trace ID
    trace_id = str(uuid.uuid4())
    print(f"Using trace ID: {trace_id}")
    
    # Extract domain from email
    domain = email.split('@')[1] if '@' in email else email
    
    # Create test trace record for foreign key constraint
    create_test_trace_record(trace_id, email, domain)
    
    # Show domain statistics before validation if requested
    if show_stats:
        print("\n📊 DOMAIN IMAP STATISTICS (BEFORE):")
        display_imap_stats(domain)
        
    # Start timer
    start_time = time.time()
    print("Starting IMAP validation...")
    
    # Initialize IMAP verifier
    try:
        imap_verifier = IMAPVerifier()
    except Exception as e:
        print(f"❌ Error initializing IMAP verifier: {e}")
        return None
    
    try:
        # Run IMAP validation
        result = imap_verifier.check_imap(domain, trace_id=trace_id)
        
        # Validate result is IMAPResult object
        if not isinstance(result, IMAPResult):
            print(f"❌ Unexpected result type: {type(result)}")
            return None
        
        # Print results
        display_imap_results(result, verbose)
        
        # Show statistics after validation if requested
        if show_stats:
            print("\n📊 DOMAIN IMAP STATISTICS (AFTER):")
            display_imap_stats(domain)
            
        return result
        
    except Exception as e:
        print(f"\n❌ Error running IMAP validation: {e}")
        logger.error(f"IMAP validation error: {e}")
        return None

def display_imap_results(result: IMAPResult, verbose=False):
    """Display IMAP validation results in a readable format"""
    print("\n" + "="*60)
    print(" 📧 IMAP VALIDATION RESULTS")
    print("="*60)
    
    # Basic info
    domain = result.domain
    has_imap = result.has_imap
    duration_ms = result.duration_ms
    
    # Show validation status with emoji
    if has_imap:
        print(f"✅ IMAP AVAILABLE for {domain}")
    else:
        print(f"❌ IMAP NOT AVAILABLE for {domain}")
    
    # Show error if any
    if result.error:
        print(f"🚫 Error: {result.error}")
    
    # Show execution time (update to ensure proper float formatting)
    print(f"⏱️  Execution time: {result.duration_ms:.2f} ms")
    print(f"🕐 Timestamp: {result.timestamp}")
    
    # Security assessment
    if has_imap:
        print(f"\n🔒 Security Level: {result.security_level.upper()}")
        
        # Security features summary
        features = []
        if result.supports_ssl:
            features.append("SSL/TLS")
        if result.supports_starttls:
            features.append("STARTTLS")
        if result.supports_oauth:
            features.append("OAuth")
            
        if features:
            print(f"🔐 Supported security features: {', '.join(features)}")
        else:
            print("⚠️  No security features detected")
            
        # Recommendations
        if result.recommendations:
            print("\n💡 Security Recommendations:")
            for i, rec in enumerate(result.recommendations, 1):
                print(f"  {i}. {rec}")
        else:
            print("\n💡 No specific recommendations")
                
        # Server details
        print(f"\n📋 Found {len(result.imap_servers)} IMAP server(s):")
        for i, server in enumerate(result.imap_servers, 1):
            print(f"\n  📧 Server {i}: {server.host}:{server.port}")
            print(f"     Protocol: {server.protocol}")
            print(f"     Secure: {'✅ Yes' if server.secure_connection else '❌ No'}")
            
            if server.banner:
                print(f"     Banner: {server.banner[:100]}{'...' if len(server.banner) > 100 else ''}")
            
            # Show capabilities if verbose
            if verbose and server.capabilities:
                print(f"     Capabilities ({len(server.capabilities)}):")
                for cap in server.capabilities[:10]:  # Show first 10
                    print(f"       - {cap}")
                if len(server.capabilities) > 10:
                    print(f"       ... and {len(server.capabilities) - 10} more")
            
            # Show additional features
            features = []
            if server.supports_starttls:
                features.append("STARTTLS")
            if server.supports_login:
                features.append("LOGIN")
            if server.supports_plain:
                features.append("PLAIN")
            if server.supports_oauth:
                features.append("OAUTH")
            if server.supports_idle:
                features.append("IDLE")
                
            if features:
                print(f"     Features: {', '.join(features)}")
    
    # Show all servers checked if verbose
    if verbose and result.servers_checked:
        print(f"\n📋 All Servers Checked ({len(result.servers_checked)}):")
        for check in result.servers_checked:
            host = check.get('host', 'unknown')
            ports = check.get('ports_checked', [])
            
            print(f"\n  🖥️  Host: {host}")
            for port_info in ports:
                port = port_info.get('port', 0)
                success = port_info.get('success', False)
                error = port_info.get('error')
                protocol = port_info.get('protocol', 'IMAP')
                
                status = "✅" if success else "❌"
                error_msg = f" - {error}" if error else ""
                print(f"    Port {port} ({protocol}): {status}{error_msg}")

def display_imap_stats(domain):
    """Display IMAP statistics for a domain from the database"""
    try:
        # Check if database is available
        if not sync_db:
            print("Database not available for statistics")
            return
            
        # Get IMAP validation history
        history = sync_db.fetchrow("""
            SELECT * FROM imap_validation_history 
            WHERE domain = $1
            ORDER BY validated_at DESC
            LIMIT 1
        """, domain)
        
        if not history:
            print(f"No IMAP validation history available for {domain}")
            return
            
        print("-"*60)
        print(f"Domain: {history.get('domain', domain)}")
        print(f"IMAP Available: {history.get('has_imap', False)}")
        print(f"Servers Found: {history.get('servers_found', 0)}")
        print(f"Security Level: {history.get('security_level', 'unknown')}")
        print(f"Supports SSL: {history.get('supports_ssl', False)}")
        print(f"Supports STARTTLS: {history.get('supports_starttls', False)}")
        print(f"Supports OAuth: {history.get('supports_oauth', False)}")
        
        # Show timestamps
        if history.get('validated_at'):
            print(f"Last Validated: {history.get('validated_at')}")
        
        # Show validation date
        if history.get('validation_date'):
            print(f"Validation Date: {history.get('validation_date')}")
        
        # Show stats
        stats = sync_db.fetchrow("""
            SELECT * FROM imap_validation_statistics 
            WHERE domain = $1
            ORDER BY created_at DESC
            LIMIT 1
        """, domain)
        
        if stats:
            print("\nValidation Statistics:")
            print(f"DNS Lookups: {stats.get('dns_lookups', 0)}")
            print(f"Processing Time: {stats.get('processing_time_ms', 0)} ms")
            print(f"Trace ID: {stats.get('trace_id', 'N/A')}")
            if stats.get('errors'):
                print(f"Errors: {stats.get('errors')}")
                
        print("-"*60)
        
    except Exception as e:
        print(f"Error retrieving IMAP statistics: {e}")
        logger.error("Database error in display_imap_stats", exc_info=True)

def test_imap_security():
    """Test IMAP security assessment with different server configurations"""
    print("\n" + "="*70)
    print(" 🔒 TESTING IMAP SECURITY ASSESSMENT")
    print("="*70)
    
    # Test domains with different security levels
    test_domains = [
        "gmail.com",       # Should be high security
        "outlook.com",     # Should be high security  
        "yahoo.com",       # Should be medium/high security
        "icloud.com",      # Should be high security
        "aol.com",         # Should be medium security
        "example.com",     # May not have IMAP
        "nonexistent12345.invalid"  # Should fail
    ]
    
    print("Testing security assessment on various email domains...")
    results = {}
    
    for i, domain in enumerate(test_domains, 1):
        print(f"\n({i}/{len(test_domains)}) Testing security for: {domain}")
        
        try:
            imap_verifier = IMAPVerifier()
            result = imap_verifier.check_imap(domain)
            
            if result.has_imap:
                security = result.security_level
                server_count = len(result.imap_servers)
                print(f"✅ IMAP available - Security: {security}, Servers: {server_count}")
                results[domain] = {
                    'security': security,
                    'available': True,
                    'servers': server_count,
                    'ssl': result.supports_ssl,
                    'starttls': result.supports_starttls,
                    'oauth': result.supports_oauth
                }
            else:
                error = result.error if result.error else "No IMAP servers found"
                print(f"❌ IMAP not available - {error}")
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

def test_imap_cache(email):
    """Test the IMAP cache functionality"""
    logger.info("="*70)
    logger.info("🗄️ TESTING IMAP CACHE")
    logger.info("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    logger.info(f"Testing cache for domain: {domain}")
    
    # Initialize IMAP verifier to get cache TTL from rate limit manager
    logger.debug("Initializing IMAP verifier")
    imap_verifier = IMAPVerifier()
    cache_ttl = imap_verifier.imap_cache_ttl
    
    # Clear any existing domain-level cache
    domain_cache_key = CacheKeys.imap(domain)
    logger.debug(f"Domain cache key: {domain_cache_key}")
    try:
        cache_manager.delete(domain_cache_key)
        logger.info("🧹 Cleared existing domain cache")
    except Exception as e:
        logger.warning(f"Error clearing cache: {e}")
    
    # Display cache TTL
    logger.info(f"IMAP cache TTL from database: {cache_ttl} seconds")
    
    # Run first check and measure time
    logger.info("\n1️⃣ First check (should miss cache):")
    start_time = time.time()
    logger.debug(f"Starting first IMAP check for {domain}")
    result1 = imap_verifier.check_imap(domain)
    duration1 = (time.time() - start_time) * 1000
    
    logger.info(f"Result: {'✅ Available' if result1.has_imap else '❌ Not available'}")
    logger.info(f"Duration: {duration1:.2f}ms")
    logger.info(f"Security: {result1.security_level}")
    
    # Log detailed results
    logger.debug(f"Found {len(result1.records)} IMAP server records")
    for idx, record in enumerate(result1.records):
        logger.debug(f"Record {idx+1}: {record.host}:{record.port} - Success: {record.success}")
        if record.success:
            logger.debug(f"  - Banner: {record.banner[:50]}...")
            logger.debug(f"  - Capabilities: {', '.join(record.capabilities[:5])}{'...' if len(record.capabilities) > 5 else ''}")
            logger.debug(f"  - TLS Info: {record.tls_info}")
    
    if result1.has_imap and result1.imap_servers:
        # Check for server capabilities cache
        first_server = result1.imap_servers[0]
        server_id = f"{first_server.host}:{first_server.port}"
        capabilities_key = CacheKeys.imap_capabilities(server_id)
        starttls_key = CacheKeys.imap_starttls(server_id)
        
        logger.info(f"\nChecking server-level caches for {server_id}:")
        logger.debug(f"Capabilities cache key: {capabilities_key}")
        logger.debug(f"STARTTLS cache key: {starttls_key}")
        
        capabilities_cache = cache_manager.get(capabilities_key)
        starttls_cache = cache_manager.get(starttls_key)
        
        has_capabilities_cache = capabilities_cache is not None
        has_starttls_cache = starttls_cache is not None
        
        logger.info(f"Capabilities cache: {'✅ Found' if has_capabilities_cache else '❌ Not found'}")
        logger.info(f"STARTTLS cache: {'✅ Found' if has_starttls_cache else '❌ Not found'}")
        
        if has_capabilities_cache:
            logger.debug(f"Cached capabilities: {capabilities_cache}")
        if has_starttls_cache:
            logger.debug(f"Cached STARTTLS info: {starttls_cache}")
    
    # Run second check and measure time
    logger.info("\n2️⃣ Second check (should hit cache):")
    start_time = time.time()
    logger.debug(f"Starting second IMAP check for {domain}")
    result2 = imap_verifier.check_imap(domain)
    duration2 = (time.time() - start_time) * 1000
    
    logger.info(f"Result: {'✅ Available' if result2.has_imap else '❌ Not available'}")
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
    """Test IMAP rate limiting functionality"""
    print("\n" + "="*70)
    print(" 🚦 TESTING IMAP RATE LIMITS")
    print("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    print(f"Testing rate limits for domain: {domain}")
    
    # Get rate limits from database
    imap_verifier = IMAPVerifier()
    connection_limit = imap_verifier.imap_connection_limit
    concurrent_limit = imap_verifier.imap_concurrent_sessions
    timeout = imap_verifier.imap_timeout
    
    print(f"Database rate limit settings:")
    print(f"Connection limit: {connection_limit}/min (category: imap, name: imap_connection_limit_per_min)")
    print(f"Concurrent sessions: {concurrent_limit} (category: imap, name: imap_concurrent_sessions)")
    print(f"Connection timeout: {timeout}s (category: imap, name: connection_timeout)")
    
    # Reset usage counters for clean test
    try:
        # Clear rate limit usage counter from cache
        cache_key = f"rate_limit:imap:imap_connection_limit_per_min:{domain}"
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
        result = imap_verifier.check_imap(domain)
        duration = (time.time() - start_time) * 1000
        
        # Check current usage count
        count = imap_verifier._get_current_imap_connections(domain)
        
        results.append({
            'call': i+1,
            'duration': duration,
            'success': result.has_imap if not result.error else False,
            'error': result.error,
            'count': count
        })
        
        print(f"  Duration: {duration:.2f}ms")
        print(f"  Current count: {count}/{connection_limit}")
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
        print(f"  Call {result['call']}: {result['duration']:.2f}ms - Count: {result['count']}/{connection_limit} - {status}")
    
    # Show rate limit utilization
    final_count = results[-1]['count'] if results else 0
    percent_used = (final_count / connection_limit) * 100 if connection_limit > 0 else 0
    print(f"\nFinal rate limit utilization: {final_count}/{connection_limit} ({percent_used:.1f}%)")
    
    if final_count >= connection_limit:
        print("✅ Successfully reached/exceeded rate limit!")
    else:
        print(f"ℹ️ Rate limit not reached ({final_count}/{connection_limit})")

def test_concurrent_connections(email, num_threads=8):
    """Test concurrent IMAP connections for rate limiting"""
    print("\n" + "="*70)
    print(" 🔄 TESTING CONCURRENT CONNECTIONS")
    print("="*70)
    
    # Extract domain
    domain = email.split('@')[1] if '@' in email else email
    print(f"Testing concurrent connections for domain: {domain}")
    
    # Get rate limits from database
    imap_verifier = IMAPVerifier()
    concurrent_limit = imap_verifier.imap_concurrent_sessions
    
    print(f"Database concurrency settings:")
    print(f"Max concurrent sessions: {concurrent_limit} (category: imap, name: imap_concurrent_sessions)")
    
    # Reset usage counters for clean test
    try:
        # Clear rate limit usage counter from cache
        cache_key = f"rate_limit:imap:imap_connection_limit_per_min:{domain}"
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
            result = imap_verifier.check_imap(domain)
            duration = (time.time() - start_time) * 1000
            
            print(f"Thread {thread_id}: Completed in {duration:.2f}ms")
            
            return {
                'thread': thread_id,
                'duration': duration,
                'success': result.has_imap if not result.error else False,
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
    """Test IMAP error handling with various problematic domains"""
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
        },
        {
            'domain': 'rate-limit-test.example',  # Special test domain for rate limiting
            'expected': 'rate limit',
            'description': 'Rate limit simulation'
        }
    ]
    
    # First, test port configuration error handling
    logger.info("\n🧪 Testing port configuration error handling:")
    try:
        # Import the port manager
        from src.managers.port import port_manager
        
        # Store original mail ports configuration
        original_mail_ports = port_manager.mail_ports
        logger.debug(f"Original mail ports count: {len(original_mail_ports) if original_mail_ports else 0}")
        
        try:
            # Test missing port configuration
            logger.info("Testing missing mail_ports configuration...")
            logger.debug("Setting mail_ports to None")
            port_manager.mail_ports = None
            
            # This should raise a ValueError
            try:
                logger.debug("Attempting to create IMAPVerifier with mail_ports=None")
                imap_verifier = IMAPVerifier()
                logger.warning("❌ Test failed: Should have raised ValueError for missing port configuration")
            except ValueError as e:
                if "Mail ports configuration missing" in str(e):
                    logger.info(f"✅ Expected error: {e}")
                else:
                    logger.warning(f"❓ Unexpected error message: {e}")
            except Exception as e:
                logger.error(f"❓ Unexpected exception type: {e}", exc_info=True)
            
            # Restore mail_ports to empty list to test empty ports
            logger.info("\nTesting empty IMAP ports in mail_ports...")
            logger.debug("Setting mail_ports to non-IMAP ports only")
            port_manager.mail_ports = [{'port': 110, 'description': 'POP3 only port'}]  # No IMAP ports
            
            # This should raise a ValueError
            try:
                logger.debug("Attempting to create IMAPVerifier with no IMAP ports")
                imap_verifier = IMAPVerifier()
                logger.warning("❌ Test failed: Should have raised ValueError for empty IMAP ports")
            except ValueError as e:
                if "Empty IMAP ports configuration" in str(e):
                    logger.info(f"✅ Expected error: {e}")
                else:
                    logger.warning(f"❓ Unexpected error message: {e}")
            except Exception as e:
                logger.error(f"❓ Unexpected exception type: {e}", exc_info=True)
                
        finally:
            # Restore original ports
            logger.debug("Restoring original mail_ports configuration")
            port_manager.mail_ports = original_mail_ports
            logger.info("\n✅ Restored original mail_ports configuration")
            
        # Verify we can create a verifier with the restored configuration
        try:
            logger.debug("Creating IMAPVerifier with restored configuration")
            imap_verifier = IMAPVerifier()
            logger.info("✅ Successfully created IMAPVerifier with restored port configuration")
        except Exception as e:
            logger.error(f"❌ Failed to create IMAPVerifier after configuration restore: {e}", exc_info=True)
            
    except ImportError as e:
        logger.error(f"❌ Could not import port_manager: {e}", exc_info=True)
        return
    except Exception as e:
        logger.error(f"❌ Could not test port configuration errors: {e}", exc_info=True)
    
    # Create an instance of IMAPVerifier for remaining tests
    try:
        logger.debug("Creating IMAPVerifier for error handling tests")
        imap_verifier = IMAPVerifier()
        logger.info("\n✅ Created IMAPVerifier with valid port configuration")
        
        # Display the loaded IMAP ports
        if hasattr(imap_verifier, "ports"):
            logger.info(f"Loaded {len(imap_verifier.ports)} IMAP ports:")
            for port_num, port_info in imap_verifier.ports.items():
                logger.info(f"  - Port {port_num}: {port_info.get('description', 'No description')}")
    except Exception as e:
        logger.error(f"\n❌ Could not create IMAPVerifier: {e}", exc_info=True)
        logger.warning("Skipping remaining error handling tests")
        return
    
    # Show error handling rate limits from database
    logger.info("\nIMAP error handling configuration (from database):")
    logger.info(f"Connect timeout: {imap_verifier.timeout_connect}s")
    logger.info(f"Read timeout: {imap_verifier.timeout_read}s")
    logger.info(f"Connection timeout: {imap_verifier.connection_timeout}s")
    logger.info(f"Max login failures: {imap_verifier.max_login_failures}/min")
    logger.info(f"Block duration after failures: {imap_verifier.block_duration_after_failures}s")
    
    # Test each error case
    for test_case in test_cases:
        domain = test_case['domain']
        expected = test_case['expected']
        description = test_case['description']
        
        logger.info(f"\n🧪 Testing: {description} ({domain})")
        logger.debug(f"Expected error pattern: {expected}")
        
        # Attempt IMAP check
        try:
            logger.debug(f"Performing IMAP check for {domain}")
            result = imap_verifier.check_imap(domain)
            
            if not result.success:
                logger.info(f"✅ Got expected failure result")
                error_found = False
                
                # Check if we got the expected error
                for record in result.records:
                    logger.debug(f"Record error: {record.error}")
                    if record.error and (expected.lower() in record.error.lower() or 
                                          any(e.lower() in record.error.lower() 
                                              for e in expected.split('|'))):
                        logger.info(f"✅ Found expected error: {record.error}")
                        error_found = True
                
                if not error_found:
                    error_strings = [r.error for r in result.records if r.error]
                    if error_strings:
                        logger.warning(f"⚠️ Got error but not the expected one: {error_strings}")
                    else:
                        logger.warning(f"⚠️ Failed but no specific error message found")
            else:
                logger.warning(f"❌ Test failed - Expected failure for {domain} but got success")
                
        except Exception as e:
            if expected.lower() in str(e).lower() or any(err.lower() in str(e).lower() for err in expected.split('|')):
                logger.info(f"✅ Got expected exception: {e}")
            else:
                logger.warning(f"❓ Got exception but not the expected one: {e}")

def test_mx_record_integration():
    """Test MX record integration with IMAP verification"""
    print("\n" + "="*70)
    print(" 🔍 TESTING MX RECORD INTEGRATION WITH IMAP")
    print("="*70)
    
    logger.info("Testing how IMAP verification uses MX records")
    
    # Initialize IMAP verifier
    try:
        imap_verifier = IMAPVerifier()
        print("✅ Successfully initialized IMAP verifier")
    except Exception as e:
        print(f"❌ Error initializing IMAP verifier: {e}")
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
    
    # Custom handler to capture log messages
    log_records = []
    
    class LogCapture(logging.Handler):
        def emit(self, record):
            log_records.append(record)
    
    # Add the log capture handler
    log_capture = LogCapture()
    logging.getLogger().addHandler(log_capture)
    
    try:
        for test in test_cases:
            input_value = test["input"]
            description = test["description"]
            expect_mx = test["expect_mx"]
            input_type = test["input_type"]
            
            print(f"\n🧪 Testing: {input_value} - {description}")
            print(f"  Input type: {input_type.upper()}")
            print(f"  Expecting MX records: {'Yes' if expect_mx else 'No'}")
            
            # Clear log records for this test
            log_records.clear()
            
            # Perform IMAP check
            try:
                result = imap_verifier.check_imap(input_value)
                print(f"  IMAP check result: {'✅ Success' if result.has_imap else '❌ Failed'}")
                
                # Analyze logs to see if MX lookup was performed
                mx_lookup_logs = [r for r in log_records if "Using original email for MX lookup" in r.getMessage() or 
                                  "Using constructed email for MX lookup" in r.getMessage()]
                
                email_mode = any("Using original email for MX lookup" in r.getMessage() for r in log_records)
                domain_mode = any("Using constructed email for MX lookup" in r.getMessage() for r in log_records)
                
                mx_records_found = any("Found " in r.getMessage() and "MX records" in r.getMessage() for r in log_records)
                fallback_pattern_logs = [r for r in log_records if "Added pattern host" in r.getMessage()]
                
                print(f"\n  MX lookup performed: {'✅ Yes' if mx_lookup_logs else '❌ No'}")
                print(f"  Using email mode: {'✅ Yes' if email_mode else '❌ No'}")
                print(f"  Using domain mode: {'✅ Yes' if domain_mode else '❌ No'}")
                print(f"  MX records found: {'✅ Yes' if mx_records_found else '❌ No'}")
                print(f"  Fallback patterns used: {'✅ Yes' if fallback_pattern_logs else '❌ No'}")
                
                # Check which hosts were actually checked
                hosts_checked = set()
                for record in result.records:
                    hosts_checked.add(record.host)
                
                # Extract domain properly regardless of input type
                domain = input_value.split('@')[1] if '@' in input_value else input_value
                
                print(f"\n  Hosts checked ({len(hosts_checked)}):")
                for host in hosts_checked:
                    if domain == host:
                        print(f"    • {host} (domain itself)")
                    elif any(host == f"{pattern}.{domain}" for pattern in ["mail", "imap", "webmail", "pop", "exchange"]):
                        print(f"    • {host} (hardcoded pattern)")
                    else:
                        print(f"    • {host} (likely from MX)")
                        
                # Verify correct lookup mode was used based on input type
                if input_type == "email" and not email_mode:
                    print(f"\n  ❌ Email address provided but email mode not used")
                elif input_type == "domain" and not domain_mode:
                    print(f"\n  ❌ Domain provided but domain mode not used")
                else:
                    print(f"\n  ✅ Correct lookup mode used for {input_type}")
                
                # Verify against expectations
                if expect_mx and not mx_records_found:
                    print(f"\n  ❌ Expected to find MX records for {input_value} but none were found")
                elif not expect_mx and mx_records_found:
                    print(f"\n  ⚠️ Did not expect MX records for {input_value} but some were found")
                elif expect_mx and mx_records_found:
                    print(f"\n  ✅ Correctly found MX records for {input_value}")
                else:
                    print(f"\n  ✅ Correctly found no MX records for {input_value}, using fallback patterns")
                    
            except Exception as e:
                print(f"  ❌ Error during IMAP check: {e}")
                
    finally:
        # Remove the log capture handler
        logging.getLogger().removeHandler(log_capture)

def test_timeout_handling():
    """Test the timeout handling in IMAP connections"""
    print("\n" + "="*70)
    print(" ⏱️ TESTING IMAP TIMEOUT HANDLING")
    print("="*70)
    
    logger.info("Testing IMAP connection timeout handling")
    
    # Initialize IMAP verifier
    try:
        imap_verifier = IMAPVerifier()
        print(f"✅ Successfully initialized IMAP verifier")
        print(f"   Connect timeout: {imap_verifier.timeout_connect}s")
        print(f"   Read timeout: {imap_verifier.timeout_read}s")
        print(f"   Connection timeout: {imap_verifier.connection_timeout}s")
    except Exception as e:
        print(f"❌ Error initializing IMAP verifier: {e}")
        return
    
    # Test cases for timeout behavior
    test_cases = [
        {
            "host": "example.com",  # Likely doesn't have IMAP
            "port": 143,
            "use_ssl": False,
            "timeout": 3.0,  # Short timeout to speed up test
            "description": "Standard connection with short timeout"
        },
        {
            "host": "10.255.255.1",  # Reserved IP that should timeout
            "port": 143,
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
            success, result = imap_verifier._connect_to_imap_server(host, port, use_ssl, timeout)
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"   Finished at: {end_time:.2f}")
            print(f"   Duration: {duration:.2f}s (timeout was set to {timeout}s)")
            
            if success:
                print(f"   ✅ Connection succeeded (unexpected for timeout test)")
                print(f"   Banner: {result.get('banner', '')[:30]}...")
                print(f"   Capabilities: {len(result.get('capabilities', []))} found")
            else:
                print(f"   ❌ Connection failed as expected")
                print(f"   Error: {result.get('error', 'No error message')}")
                
            # Check if timeout was respected (allow small buffer for processing)
            if not success and "timeout" in result.get('error', '').lower():
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
    """Test all three cache mechanisms used in IMAP verification"""
    print("\n" + "="*70)
    print(" 🗂️ TESTING COMPREHENSIVE IMAP CACHE MECHANISM")
    print("="*70)
    
    # Initialize IMAP verifier
    try:
        imap_verifier = IMAPVerifier()
        print("✅ Successfully initialized IMAP verifier")
        print(f"   Cache TTL: {imap_verifier.imap_cache_ttl}s")
    except Exception as e:
        print(f"❌ Error initializing IMAP verifier: {e}")
        return
    
    # Choose a test domain
    domain = "gmail.com"  # Should have IMAP
    print(f"Testing with domain: {domain}")
    
    # Clear all caches related to this domain
    domain_cache_key = CacheKeys.imap(domain)
    cache_manager.delete(domain_cache_key)
    print(f"✓ Cleared domain cache: {domain_cache_key}")
    
    # First check creates all caches
    print("\n1️⃣ First check - should miss all caches:")
    start_time = time.time()
    result1 = imap_verifier.check_imap(domain)
    duration1 = (time.time() - start_time) * 1000
    
    print(f"   Duration: {duration1:.2f}ms")
    print(f"   Success: {'✅ Yes' if result1.has_imap else '❌ No'}")
    print(f"   Servers found: {len(result1.imap_servers)}")
    
    # Find all servers to check caches for
    print("\n📊 Checking caches for each server:")
    
    # Check domain-level cache
    domain_cache = cache_manager.get(domain_cache_key)
    print(f"\n📂 Domain cache ({domain_cache_key}):")
    print(f"   {'✅ Found' if domain_cache else '❌ Not found'}")
    
    # Check server-level caches if available
    if result1.has_imap and result1.imap_servers:
        for i, server in enumerate(result1.imap_servers, 1):
            server_id = f"{server.host}:{server.port}"
            capabilities_key = CacheKeys.imap_capabilities(server_id)
            starttls_key = CacheKeys.imap_starttls(server_id)
            
            print(f"\n📂 Server {i}: {server_id}")
            print(f"   Capabilities cache ({capabilities_key}):")
            capabilities_cache = cache_manager.get(capabilities_key)
            print(f"   {'✅ Found' if capabilities_cache else '❌ Not found'}")
            
            print(f"   STARTTLS cache ({starttls_key}):")
            starttls_cache = cache_manager.get(starttls_key)
            print(f"   {'✅ Found' if starttls_cache else '❌ Not found'}")
    
    # Second check should hit all caches
    print("\n2️⃣ Second check - should hit domain cache:")
    start_time = time.time()
    result2 = imap_verifier.check_imap(domain)
    duration2 = (time.time() - start_time) * 1000
    
    print(f"   Duration: {duration2:.2f}ms")
    print(f"   Success: {'✅ Yes' if result2.has_imap else '❌ No'}")
    print(f"   Servers found: {len(result2.imap_servers)}")
    
    # Compare performance
    speedup = (duration1 - duration2) / duration1 * 100
    print(f"\n⚡ Performance: {speedup:.1f}% faster (from {duration1:.1f}ms to {duration2:.1f}ms)")
    
    if speedup > 50:
        print("✅ Significant speedup indicates caching is working properly")
    elif duration2 < 20:
        print("✅ Very fast response time indicates caching is working properly")
    else:
        print("⚠️ Cache may not be working optimally")
        
def main():
    """Main function to parse command line args and run tests"""
    # Parse command line arguments
    show_stats = '--stats' in sys.argv
    verbose = '--verbose' in sys.argv
    test_security = '--security' in sys.argv
    test_cache = '--test-cache' in sys.argv
    test_rate_limits_flag = '--test-rate-limits' in sys.argv
    test_concurrent = '--test-concurrent' in sys.argv
    test_errors = '--test-errors' in sys.argv
    test_mx_integration = '--test-mx' in sys.argv
    test_timeouts = '--test-timeouts' in sys.argv  # New option
    test_all_caches = '--test-all-caches' in sys.argv  # New option
    
    # Print header
    print("="*70)
    print(" 📧 IMAP VALIDATION ENGINE TEST SUITE")
    print("="*70)
    
    # Show database rate limits
    try:
        # Get IMAP limits from database
        rate_manager = RateLimitManager()
        imap_limits = rate_manager.get_imap_limits()
        
        print("\n📊 IMAP Rate Limits from Database:")
        print(f"{'Name':<30} {'Value':<10} {'Type':<8} {'Enabled'}")
        print("-"*70)
        
        for name, info in imap_limits.items():
            value = info.get('value', 'N/A')
            is_time = "Time" if info.get('is_time', False) else "Count"
            enabled = "✅" if info.get('enabled', True) else "❌"
            
            print(f"{name:<30} {value:<10} {is_time:<8} {enabled}")
            
        print("-"*70)
    except Exception as e:
        print(f"Unable to retrieve rate limits: {e}")
    
    # Test timeout handling 
    if test_timeouts:
        test_timeout_handling()
        return
    
    # Test all caching mechanisms
    if test_all_caches:
        test_cache_mechanism()
        return
    
    # If testing MX integration (new option)
    if test_mx_integration:
        test_mx_record_integration()
        return
    
    # If testing security assessment
    if test_security:
        test_imap_security()
        return
        
    # If testing cache
    if test_cache:
        # Get the domain from arguments
        email_arg = None
        for arg in sys.argv[1:]:
            if not arg.startswith('-') and '@' in arg:
                email_arg = arg
                break
                
        if email_arg:
            test_imap_cache(email_arg)
        else:
            test_imap_cache("test@gmail.com")  # Default domain
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
        test_imap(email_arg, show_stats, verbose)
    else:
        # Use sample emails
        sample_emails = [
            # Valid popular email domains - these should work
            "test@gmail.com",
            "info@outlook.com",
            "test@yahoo.com",
            
            # Valid but different providers
            "test@icloud.com",
            "test@protonmail.com",
            
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
        print(f"  --test-mx           Test MX record integration with IMAP")
        print(f"  --test-timeouts     Test connection timeout handling")
        print(f"  --test-all-caches   Test all 3 types of IMAP caches")
        
        print(f"\n🧪 Running comprehensive test on {len(sample_emails)} domains...\n")
        
        for i, email in enumerate(sample_emails, 1):
            print(f"\n{'#'*70}")
            print(f"TEST {i}/{len(sample_emails)}: {email}")
            print(f"{'#'*70}")
            try:
                result = test_imap(email, show_stats, verbose)
                if result:
                    print(f"✅ Test completed successfully")
                else:
                    print(f"❌ Test failed or returned no result")
            except Exception as e:
                print(f"❌ Error testing {email}: {e}")
                logger.error(f"Test error for {email}", exc_info=True)
            
            # Pause between tests
            if i < len(sample_emails):
                print("\n⏳ Pausing for 3 seconds before next test...")
                time.sleep(3)
        
        print(f"\n🎉 Completed all {len(sample_emails)} tests!")

if __name__ == "__main__":
    main()