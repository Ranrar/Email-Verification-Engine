"""
DNS Manager Tester for Email Verification Engine
================================================

This script tests the DNS resolution and statistics functionality of the Email Verification Engine.
It allows testing DNS resolution, nameserver selection, and viewing statistics.

Usage:
  # From project root
  python src/Test/test_dns.py example.com --type=MX  # Test specific domain with record type
  python src/Test/test_dns.py example.com --stats     # Test domain and display statistics
  python src/Test/test_dns.py --nameservers           # List configured nameservers
  python src/Test/test_dns.py --benchmark             # Run performance benchmark tests
  python src/Test/test_dns.py --warmup                # Enable stats and run test queries
  python src/Test/test_dns.py --clean                 # Clean up old statistics
  
  # Statistics collection
  DNS statistics are only stored if collection is enabled in settings.
  Use --warmup to ensure statistics collection is enabled.
  
  # Combined options
  python src/Test/test_dns.py --warmup --stats        # Initialize stats and display
  python src/Test/test_dns.py gmail.com --warmup       # Test domain with stats enabled
  
  # Or run with sample domains
  python src/Test/test_dns.py                         # Test sample domains
"""

# idear.. maby create a DNS warmup function, when the application starts to not start with no stats

import sys
import os
import time
import json
from datetime import datetime, timedelta
from pprint import pprint

# Add project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

# Now import from the project structure
from src.managers.dns import DNSManager
from src.engine.functions.statistics import DNSServerStats
from src.managers.log import Axe
from src.helpers.dbh import sync_db

# Initialize logger and managers
logger = Axe()
dns_manager = DNSManager()
dns_manager.initialize()

def test_dns_resolution(domain, record_types=None):
    """
    Test DNS resolution for a domain with various record types
    
    Args:
        domain: Domain to test
        record_types: List of record types to test, or None for defaults
    """
    if record_types is None:
        record_types = ['A', 'MX', 'TXT', 'AAAA']
        
    print(f"\n=== Testing DNS Resolution for {domain} ===")
    
    success_count = 0
    fail_count = 0
    
    for record_type in record_types:
        print(f"\nResolving {record_type} records for {domain}:")
        
        try:
            start_time = time.time()
            answers = dns_manager.resolve(domain, record_type)
            duration_ms = (time.time() - start_time) * 1000
            
            # Print results
            print(f"✅ Found {len(answers)} {record_type} record(s) in {duration_ms:.2f}ms:")
            print("-" * 60)
            
            for rdata in answers:
                print(f"  {rdata.to_text()}")
                
            success_count += 1
                
        except Exception as e:
            print(f"❌ Failed to resolve {record_type} records: {str(e)}")
            fail_count += 1
            
    print("\n=== Summary ===")
    print(f"Total record types tested: {len(record_types)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {fail_count}")
    
def test_nameserver_selection():
    """Test the nameserver selection strategies"""
    print("\n=== Testing Nameserver Selection ===")
    
    # Test all three strategies
    strategies = {
        1: "Random",
        2: "Round-robin",
        3: "Best performer"
    }
    
    # Get all available nameservers for reference
    all_nameservers = dns_manager.get_nameservers_from_db()
    print(f"Total available nameservers: {len(all_nameservers)}")
    
    for strategy_id, strategy_name in strategies.items():
        # Temporarily set the strategy
        original_strategy = dns_manager.get_selection_strategy()
        dns_manager.update_setting('selection_strategy', strategy_id)
        
        print(f"\nTesting strategy: {strategy_id} - {strategy_name}")
        
        # Select nameservers multiple times to see patterns
        for i in range(3):
            selected = dns_manager.select_nameservers(count=2)
            print(f"Selection {i+1}: {', '.join(selected)}")
            
        # Restore original strategy
        dns_manager.update_setting('selection_strategy', original_strategy)
    
def display_nameserver_stats():
    """Display statistics about nameserver performance"""
    print("\n=== DNS Nameserver Statistics ===")
    
    try:
        # Get aggregate stats from database
        rows = sync_db.fetch("""
            SELECT 
                nameserver, 
                SUM(queries) as total_queries,
                SUM(hits) as total_hits,
                SUM(errors) as total_errors,
                AVG(avg_latency_ms) as avg_latency
            FROM dns_server_stats
            GROUP BY nameserver
            ORDER BY total_queries DESC
        """)
        
        if not rows:
            print("No nameserver statistics available yet.")
            return
            
        print(f"Statistics for {len(rows)} nameservers:")
        print("-" * 70)
        print(f"{'Nameserver':<20} {'Queries':<10} {'Success %':<10} {'Avg Latency':<15} {'Errors':<10}")
        print("-" * 70)
        
        for row in rows:
            nameserver = row['nameserver']
            queries = row['total_queries']
            hits = row['total_hits'] or 0
            errors = row['total_errors'] or 0
            latency = row['avg_latency'] or 0
            
            success_rate = (hits / queries * 100) if queries > 0 else 0
            
            print(f"{nameserver:<20} {queries:<10} {success_rate:>6.1f}%     {latency:>6.2f}ms      {errors:<10}")
            
        # Also show recent queries - using the correct column names from your schema
        print("\nRecent DNS server activity:")
        recent = sync_db.fetch("""
            SELECT 
                nameserver, 
                query_type, 
                hits, 
                misses,
                errors,
                avg_latency_ms,
                last_updated
            FROM dns_server_stats
            ORDER BY last_updated DESC
            LIMIT 10
        """)
        
        if recent:
            print("-" * 90)
            print(f"{'Last Updated':<20} {'Server':<18} {'Type':<8} {'Hits':<8} {'Misses':<8} {'Errors':<8} {'Avg Latency':<10}")
            print("-" * 90)
            
            for record in recent:
                time_str = record['last_updated'].strftime('%Y-%m-%d %H:%M:%S') if record['last_updated'] else 'N/A'
                nameserver = record['nameserver'][:16]
                query_type = record['query_type']
                hits = record['hits']
                misses = record['misses']
                errors = record['errors']
                latency = f"{record['avg_latency_ms']:.2f}" if record['avg_latency_ms'] else "-"
                
                print(f"{time_str:<20} {nameserver:<18} {query_type:<8} {hits:<8} {misses:<8} {errors:<8} {latency:<10}ms")
    
    except Exception as e:
        print(f"Error retrieving DNS statistics: {e}")

def list_nameservers():
    """List all configured nameservers"""
    print("\n=== Configured Nameservers ===")
    
    try:
        nameservers = dns_manager.get_nameservers_from_db(include_ipv6=True, active_only=False)
        
        if not nameservers:
            print("No nameservers configured in database.")
            return
            
        print(f"Found {len(nameservers)} nameservers:")
        print("-" * 95)
        print(f"{'IP Address':<20} {'Version':<8} {'Provider':<15} {'Priority':<8} {'Active':<6} {'DNSSEC':<6} {'EDNS':<6} {'Description':<20}")
        print("-" * 95)
        
        for ns in nameservers:
            print(f"{ns['ip_address']:<20} {ns['version']:<8} {ns['provider']:<15} {ns['priority']:<8} {'✓' if ns['is_active'] else '✗':<6} {'✓' if ns['supports_dnssec'] else '✗':<6} {'✓' if ns['supports_edns'] else '✗':<6} {(ns['description'] or '')[:20]}")
            
    except Exception as e:
        print(f"Error retrieving nameservers: {e}")

def run_dns_benchmark(target_domains=None, iterations=10):
    """Run a DNS benchmark test on multiple domains"""
    if target_domains is None:
        target_domains = [
            'gmail.com',
            'yahoo.com',
            'hotmail.com',
            'outlook.com',
            'aol.com',
            'protonmail.com',
            'icloud.com',
            'zoho.com',
            'mail.com'
        ]
    
    print("\n=== DNS Benchmark Test ===")
    print(f"Testing {len(target_domains)} domains with {iterations} iterations each")
    
    # Dictionary to store results by nameserver and domain
    results = {}
    
    # Get both DNS strategies
    original_strategy = dns_manager.get_selection_strategy()
    
    try:
        # Test with different nameserver selection strategies
        for strategy in [2, 3]:  # Round-robin (2) and Best performer (3)
            dns_manager.update_setting('selection_strategy', strategy)
            strategy_name = "Round-robin" if strategy == 2 else "Best performer"
            
            print(f"\nTesting with nameserver selection strategy: {strategy_name}")
            
            # Track overall stats for this strategy
            total_time = 0
            success_count = 0
            
            # Test each domain
            for domain in target_domains:
                domain_success = 0
                domain_time = 0
                
                print(f"\nBenchmarking {domain}...")
                for i in range(iterations):
                    try:
                        # Get the nameserver that will be used
                        nameservers = dns_manager.select_nameservers(1)
                        nameserver = nameservers[0] if nameservers else "unknown"
                        
                        # Initialize the nameserver in results if needed
                        if nameserver not in results:
                            results[nameserver] = {
                                'total_queries': 0,
                                'successful': 0,
                                'total_time_ms': 0,
                                'by_domain': {}
                            }
                        
                        # Resolve the domain
                        start_time = time.time()
                        dns_manager.resolve(domain, 'MX')
                        duration_ms = (time.time() - start_time) * 1000
                        
                        # Record success
                        success_count += 1
                        domain_success += 1
                        domain_time += duration_ms
                        total_time += duration_ms
                        
                        # Update results
                        results[nameserver]['total_queries'] += 1
                        results[nameserver]['successful'] += 1
                        results[nameserver]['total_time_ms'] += duration_ms
                        
                        # Update domain-specific stats
                        if domain not in results[nameserver]['by_domain']:
                            results[nameserver]['by_domain'][domain] = {
                                'queries': 0,
                                'successful': 0,
                                'total_time_ms': 0
                            }
                        results[nameserver]['by_domain'][domain]['queries'] += 1
                        results[nameserver]['by_domain'][domain]['successful'] += 1
                        results[nameserver]['by_domain'][domain]['total_time_ms'] += duration_ms
                        
                        # Progress indicator
                        sys.stdout.write(f"\r  Progress: {i+1}/{iterations} queries completed")
                        sys.stdout.flush()
                        
                    except Exception as e:
                        # Get the nameserver that would have been used
                        nameservers = dns_manager.select_nameservers(1)
                        nameserver = nameservers[0] if nameservers else "unknown"
                        
                        # Record failure
                        if nameserver not in results:
                            results[nameserver] = {
                                'total_queries': 0,
                                'successful': 0,
                                'total_time_ms': 0,
                                'by_domain': {}
                            }
                        results[nameserver]['total_queries'] += 1
                        if domain not in results[nameserver]['by_domain']:
                            results[nameserver]['by_domain'][domain] = {
                                'queries': 0,
                                'successful': 0,
                                'total_time_ms': 0
                            }
                        results[nameserver]['by_domain'][domain]['queries'] += 1
                
                # Domain summary
                avg_time = domain_time / domain_success if domain_success > 0 else 0
                success_rate = domain_success / iterations * 100
                print(f"\r  Results: {domain_success}/{iterations} successful ({success_rate:.1f}%), avg time: {avg_time:.2f}ms")
            
            # Strategy summary
            avg_time = total_time / success_count if success_count > 0 else 0
            total_queries = iterations * len(target_domains)
            success_rate = success_count / total_queries * 100
            print(f"\nStrategy summary - {strategy_name}:")
            print(f"  Total queries: {total_queries}")
            print(f"  Successful queries: {success_count} ({success_rate:.1f}%)")
            print(f"  Average response time: {avg_time:.2f}ms")
    
    finally:
        # Restore original strategy
        dns_manager.update_setting('selection_strategy', original_strategy)
    
    # Print detailed results by nameserver
    print("\n=== Detailed Results by Nameserver ===")
    for nameserver, stats in results.items():
        avg_time = stats['total_time_ms'] / stats['successful'] if stats['successful'] > 0 else 0
        success_rate = stats['successful'] / stats['total_queries'] * 100 if stats['total_queries'] > 0 else 0
        print(f"\nNameserver: {nameserver}")
        print(f"  Queries: {stats['total_queries']}")
        print(f"  Success rate: {success_rate:.1f}%")
        print(f"  Average response time: {avg_time:.2f}ms")

def clean_old_statistics():
    """Clean up old statistics"""
    print("\n=== Cleaning Old Statistics ===")
    
    try:
        dns_stats = DNSServerStats()
        count = dns_stats.clean_up_old_stats(days=30)
        print(f"Cleaned up {count} old statistics records.")
    except Exception as e:
        print(f"Error cleaning statistics: {e}")

def warmup_dns_stats():
    """
    Warm up the DNS statistics by ensuring collection is enabled 
    and running some test queries
    """
    print("\n=== Warming Up DNS Statistics ===")
    
    # Ensure statistics collection is enabled
    try:
        if not dns_manager.get_collect_stats():
            print("Enabling DNS statistics collection...")
            dns_manager.update_setting('collect_stats', '1')
        else:
            print("DNS statistics collection is enabled.")
            
        # Run some test queries to popular domains
        warmup_domains = ['google.com', 'microsoft.com', 'amazon.com']
        record_types = ['A', 'MX']
        
        print("Performing warmup DNS queries...")
        for domain in warmup_domains:
            for record_type in record_types:
                try:
                    print(f"  Querying {record_type} records for {domain}...")
                    dns_manager.resolve(domain, record_type)
                    print("  ✓ Success")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    
        print("DNS warmup complete. Statistics should now be available.")
        
    except Exception as e:
        print(f"Error during DNS warmup: {e}")

def run_interactive_mode():
    """Run the DNS tester in interactive mode with a menu"""
    clear_screen()
    print("=" * 70)
    print("              DNS MANAGER TEST TOOL - INTERACTIVE MODE")
    print("=" * 70)
    
    while True:
        print("\nSelect a test to run:")
        print("  1. Test DNS resolution for a domain")
        print("  2. List configured nameservers")
        print("  3. View DNS statistics")
        print("  4. Run benchmark tests")
        print("  5. Warm up DNS statistics")
        print("  6. Clean up old statistics")
        print("  7. Test nameserver selection strategies")
        print("  8. Run quick tests on sample domains")
        print("  0. Exit")
        
        choice = input("\nEnter your choice (0-8): ").strip()
        
        if choice == '0':
            print("Exiting DNS test tool.")
            break
            
        elif choice == '1':
            domain = input("Enter domain to test (e.g., example.com): ").strip()
            if not domain:
                print("No domain entered, returning to menu.")
                continue
                
            record_type_map = {
                '1': 'A', 
                '2': 'MX', 
                '3': 'TXT', 
                '4': 'AAAA',
                '5': 'NS',
                '6': 'CNAME',
                '7': 'SRV',
                '8': 'PTR',
            }
            
            print("\nSelect record type:")
            for key, value in record_type_map.items():
                print(f"  {key}. {value}")
            print("  9. All common types")
            
            rec_choice = input("Enter your choice (1-9): ").strip()
            
            if rec_choice == '9':
                test_dns_resolution(domain)
            elif rec_choice in record_type_map:
                test_dns_resolution(domain, [record_type_map[rec_choice]])
            else:
                print("Invalid record type selection.")
            
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '2':
            list_nameservers()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '3':
            display_nameserver_stats()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '4':
            print("\nRunning DNS benchmark test. This may take a few minutes...")
            run_dns_benchmark()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '5':
            warmup_dns_stats()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '6':
            clean_old_statistics()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '7':
            test_nameserver_selection()
            input("\nPress Enter to continue...")
            clear_screen()
            
        elif choice == '8':
            run_quick_tests()
            input("\nPress Enter to continue...")
            clear_screen()
            
        else:
            print("Invalid choice, please try again.")

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_quick_tests():
    """Run a quick set of tests on sample domains"""
    sample_domains = [
        "gmail.com",
        "microsoft.com",
        "yahoo.com",
        "nonexistentdomain123456789.com"  # Should fail
    ]
    
    print("\n=== Running Quick Tests on Sample Domains ===")
    for domain in sample_domains:
        test_dns_resolution(domain, ['A', 'MX'])  # Just test A and MX for speed
        print("\n" + "="*60 + "\n")

def main():
    """Main function to parse arguments and run tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Manager Tester')
    parser.add_argument('domain', nargs='?', help='Domain or email to test')
    parser.add_argument('--type', '-t', default='MX', help='DNS record type to test (A, MX, TXT, etc.)')
    parser.add_argument('--stats', '-s', action='store_true', help='Display DNS statistics')
    parser.add_argument('--nameservers', '-n', action='store_true', help='List configured nameservers')
    parser.add_argument('--benchmark', '-b', action='store_true', help='Run DNS benchmark tests')
    parser.add_argument('--clean', action='store_true', help='Clean up old statistics')
    parser.add_argument('--warmup', '-w', action='store_true', help='Warm up DNS statistics')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive menu mode')
    
    args = parser.parse_args()
    
    # Interactive mode overrides other arguments
    if args.interactive:
        run_interactive_mode()
        return
    
    # Run warmup first if requested
    if args.warmup:
        warmup_dns_stats()
    
    # Run requested tests
    if args.nameservers:
        list_nameservers()
    
    if args.stats:
        display_nameserver_stats()
        
    if args.clean:
        clean_old_statistics()
    
    if args.benchmark:
        run_dns_benchmark()
        
    # If a domain was provided, test it
    if args.domain:
        if '@' in args.domain:
            # Extract domain from email
            domain = args.domain.split('@')[1].strip().lower()
        else:
            domain = args.domain.strip().lower()
            
        test_dns_resolution(domain, [args.type])
        test_nameserver_selection()
    
    # If no specific action was requested, run interactive mode
    if not (args.domain or args.nameservers or args.stats or args.benchmark or args.clean or args.warmup):
        run_interactive_mode()

if __name__ == "__main__":
    main()