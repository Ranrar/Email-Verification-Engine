"""
Email Verification Engine
===================================
DNS Warmup Module:
Checks and ensures DNS statistics are present and up-to-date.
This module can be run as a standalone script or imported during application startup.

Run directly from command line: python src/helpers/dns_warmup.py
Or with options: python src/helpers/dns_warmup.py --force --max-age=12 --verbose
"""

import sys
import os
import time
from datetime import datetime, timedelta
import logging

# Add project root directory to Python path when run as a script
if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    sys.path.insert(0, project_root)

from src.managers.dns import DNSManager
from src.engine.functions.statistics import DNSServerStats
from src.helpers.dbh import sync_db
from src.managers.log import Axe
from src.managers.time import now_utc, normalize_datetime

# Initialize logger
logger = Axe()

class DNSWarmup:
    """
    Class to handle DNS warmup operations
    """
    
    def __init__(self, dns_manager=None):
        """Initialize with optional DNS manager instance"""
        self.dns_manager = dns_manager or DNSManager()
        if not hasattr(self.dns_manager, '_initialized') or not self.dns_manager._initialized:
            self.dns_manager.initialize()
        
        self.dns_stats = DNSServerStats()
    
    def check_if_warmup_needed(self, max_age_hours=24):
        """
        Check if DNS statistics need warming up
        
        Args:
            max_age_hours: Maximum age of statistics in hours before warmup is needed
            
        Returns:
            tuple: (warmup_needed, reason)
        """
        try:
            # Check if stats collection is enabled
            if not self.dns_manager.get_collect_stats():
                logger.info("DNS statistics collection is disabled in settings")
                return False, "collection_disabled"
                
            # Check if ANY statistics exist
            stats_count = sync_db.fetchrow(
                "SELECT COUNT(*) as count FROM dns_server_stats"
            )
            
            if not stats_count or stats_count['count'] == 0:
                logger.info("No DNS statistics found - warmup needed")
                return True, "no_stats"
            
            # Check the most recent activity timestamp
            latest = sync_db.fetchrow(
                "SELECT MAX(last_updated) as latest FROM dns_server_stats"
            )
            
            if not latest or not latest['latest']:
                logger.info("No valid timestamp on DNS statistics - warmup needed")
                return True, "no_timestamp"
                
            # Calculate age in hours using timezone-aware functions
            latest_timestamp = latest['latest']
            current_time = now_utc()
            normalized_timestamp = normalize_datetime(latest_timestamp)
            if normalized_timestamp is None:
                logger.info("Invalid timestamp on DNS statistics - warmup needed")
                return True, "invalid_timestamp"
            age = current_time - normalized_timestamp
            age_hours = age.total_seconds() / 3600
            
            if age_hours > max_age_hours:
                logger.info(f"DNS statistics are {age_hours:.1f} hours old (maximum {max_age_hours}h) - warmup needed")
                return True, f"too_old:{age_hours:.1f}_hours"
                
            # Check if we have enough stats for each active nameserver
            active_ns_count = sync_db.fetchrow(
                "SELECT COUNT(*) as count FROM dns_nameservers WHERE is_active = TRUE"
            )
            
            if active_ns_count and active_ns_count['count'] > 0:
                # Count distinct nameservers in stats
                stats_ns_count = sync_db.fetchrow(
                    "SELECT COUNT(DISTINCT nameserver) as count FROM dns_server_stats"
                )
                
                if not stats_ns_count or stats_ns_count['count'] < active_ns_count['count']:
                    logger.info(f"Only {stats_ns_count['count'] if stats_ns_count else 0} of {active_ns_count['count']} nameservers have statistics - warmup needed")
                    return True, "missing_nameservers"
            
            # If we got here, no warmup needed
            logger.info("DNS statistics are current and complete")
            return False, "stats_current"
            
        except Exception as e:
            logger.error(f"Error checking DNS statistics: {e}")
            # Default to requiring warmup if check fails
            return True, f"error:{str(e)}"
    
    def run_warmup(self, test_domains=None, record_types=None):
        """
        Run DNS statistics warmup
        
        Args:
            test_domains: List of domains to test (defaults to popular sites)
            record_types: List of record types to test (defaults to common types)
            
        Returns:
            dict: Summary of warmup results
        """
        if test_domains is None:
            test_domains = ['google.com', 'microsoft.com', 'amazon.com']
            
        if record_types is None:
            record_types = ['A', 'MX', 'TXT']

        logger.info("Starting DNS statistics warmup")
        start_time = time.time()
        
        # Ensure statistics collection is enabled
        if not self.dns_manager.get_collect_stats():
            logger.info("Enabling DNS statistics collection...")
            self.dns_manager.update_setting('collect_stats', '1')
        
        # Get all active nameservers from database
        # For IPv6, only include if the system supports it
        from src.helpers.ipv6_resolver import IPv6Resolver
        ipv6_resolver = IPv6Resolver()
        ipv6_available = ipv6_resolver.is_available()
        
        logger.info(f"IPv6 availability: {ipv6_available}")
        
        # Initialize the variable outside the try block
        ipv6_preference_changed = False
        
        # Check if IPv6 availability matches preference setting
        try:
            current_prefer_ipv6 = self.dns_manager._get_setting_with_fallback('prefer_ipv6', '1', log_level="debug")
            
            # If IPv6 is available but preference is disabled, enable it
            if ipv6_available and current_prefer_ipv6 != '1':
                logger.info("IPv6 is available. Enabling IPv6 preference in settings.")
                self.dns_manager.update_setting('prefer_ipv6', '1')
                ipv6_preference_changed = True
            
            # If IPv6 is NOT available but preference is enabled, disable it 
            elif not ipv6_available and current_prefer_ipv6 != '0':
                logger.warning("IPv6 is not available. Disabling IPv6 preference in settings.")
                self.dns_manager.update_setting('prefer_ipv6', '0')
                ipv6_preference_changed = True
            else:
                logger.info(f"IPv6 preference setting already correct (available: {ipv6_available}, setting: {current_prefer_ipv6})")
                
        except Exception as e:
            logger.error(f"Failed to check or update IPv6 preference setting: {e}")
            # Variable is already initialized to False, so we're safe
    
        nameservers = self.dns_manager.get_nameservers_from_db(include_ipv6=ipv6_available)
        
        if not nameservers:
            logger.warning("No nameservers found in database")
            return {
                'success': False,
                'reason': 'no_nameservers',
                'duration_ms': (time.time() - start_time) * 1000
            }
        
        logger.info(f"Found {len(nameservers)} nameservers to test")
        
        # Track success metrics
        success_count = 0
        failure_count = 0
        
        # Test each nameserver individually with only one query per type
        # This is a targeted warmup just to get basic stats
        for ns in nameservers:
            nameserver_ip = ns['ip_address']
            
            # Skip nameserver if it's IPv6 but IPv6 is not available
            if ':' in nameserver_ip and not ipv6_available:
                logger.info(f"Skipping IPv6 nameserver {nameserver_ip} due to lack of IPv6 support")
                continue
                
            logger.info(f"Testing nameserver: {nameserver_ip} ({ns['provider']})")
            
            # For each domain, try just one record type to minimize unnecessary tests
            for domain_index, domain in enumerate(test_domains):
                # Cycle through record types to ensure coverage
                record_type = record_types[domain_index % len(record_types)]
                
                try:
                    # Run resolver with specific nameserver
                    if ':' in nameserver_ip:  # IPv6
                        test_resolver = ipv6_resolver
                    else:  # IPv4
                        from src.helpers.ipv4_resolver import IPv4Resolver
                        test_resolver = IPv4Resolver()
                    
                    logger.info(f"Querying {record_type} records for {domain} using {nameserver_ip}")
                    start_query = time.time()
                    answers = test_resolver.resolve(
                        hostname=domain,
                        record_type=record_type,
                        nameservers=[nameserver_ip],
                        timeout=float(self.dns_manager.get_timeout())
                    )
                    duration_ms = (time.time() - start_query) * 1000
                    
                    # Record statistics
                    self.dns_stats.record_query_stats(
                        nameserver_ip,
                        record_type,
                        'success',
                        duration_ms
                    )
                    
                    success_count += 1
                    logger.info(f"Success - {len(answers)} records in {duration_ms:.1f}ms")
                    
                except Exception as e:
                    # Record failure
                    self.dns_stats.record_query_stats(
                        nameserver_ip,
                        record_type,
                        'failure',
                        None,
                        str(e)
                    )
                    
                    failure_count += 1
                    logger.debug(f"Failed - {str(e)}")
        
        # Calculate summary
        total_queries = success_count + failure_count
        success_rate = (success_count / total_queries * 100) if total_queries > 0 else 0
        duration_ms = (time.time() - start_time) * 1000
        
        logger.info(f"DNS warmup completed in {duration_ms:.1f}ms")
        logger.info(f"Success rate: {success_rate:.1f}% ({success_count}/{total_queries} successful)")
        
        return {
            'success': True,
            'total_queries': total_queries,
            'successful_queries': success_count,
            'success_rate': success_rate,
            'duration_ms': duration_ms,
            'ipv6_preference_changed': ipv6_preference_changed
        }

def check_and_warmup(force=False, max_age_hours=24):
    """
    Check if warmup is needed and run if necessary
    
    Args:
        force: Force warmup regardless of checks
        max_age_hours: Maximum age in hours before warmup is triggered
        
    Returns:
        dict: Result summary
    """
    warmup = DNSWarmup()
    
    if not force:
        needed, reason = warmup.check_if_warmup_needed(max_age_hours)
        if not needed:
            return {
                'performed': False,
                'reason': reason
            }
    
    # Run warmup
    result = warmup.run_warmup()
    result['performed'] = True
    return result

if __name__ == "__main__":
    # Run as a standalone script
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Statistics Warmup')
    parser.add_argument('--force', '-f', action='store_true', help='Force warmup regardless of current stats')
    parser.add_argument('--max-age', '-m', type=int, default=24, help='Maximum age (hours) of statistics before warmup')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        # Set logger to debug if available
        pass
    
    # Run check and warmup
    print("DNS Statistics Warmup Process")
    print("=============================")
    
    start = time.time()
    result = check_and_warmup(args.force, args.max_age)
    duration = time.time() - start
    
    if result['performed']:
        print(f"Warmup performed: {result['success_rate']:.1f}% success rate")
        print(f"Tested {result['total_queries']} queries in {result['duration_ms']/1000:.1f} seconds")
    else:
        print(f"Warmup not needed: {result['reason']}")
    
    print(f"\nTotal execution time: {duration:.2f} seconds")