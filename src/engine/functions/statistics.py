"""
Email Verification Engine
=====================
Domain Statistics Tracking Module

This module handles the collection, updating and retrieval of SMTP domain statistics:
1. Tracking success/failure rates for domains
2. Managing retry availability based on exponential backoff
3. Recording performance metrics for SMTP connections
4. Maintaining domain-specific error statistics
"""

import time
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime, timezone, timedelta
import decimal

from src.managers.log import Axe
from src.helpers.dbh import sync_db

# Initialize logging
logger = Axe()

class DomainStats:
    """Manages domain statistics for SMTP operations"""

    def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Get domain statistics and settings from database using UPSERT pattern"""
        try:
            # Use a single query with INSERT ... ON CONFLICT DO NOTHING
            sync_db.execute(
                """
                INSERT INTO smtp_domain_stats (domain)
                VALUES ($1)
                ON CONFLICT (domain) DO NOTHING
                """,
                domain
            )
            
            # Now get the record which will definitely exist
            result = sync_db.fetchrow(
                """
                SELECT * FROM smtp_domain_stats 
                WHERE domain = $1
                """, 
                domain
            )
            
            return result or {}
        except Exception as e:
            logger.warning(f"Failed to get domain stats for {domain}: {e}")
            return {}

    def update_domain_stats(self, domain: str, success: bool, 
                        response_time_ms: int = 0, error_code: Optional[int] = None,
                        error_type: Optional[str] = None, trace_id: Optional[str] = None,
                        mx_host: Optional[str] = None, port: Optional[int] = None):
        """Update domain statistics after an attempt"""
        try:
            current_time = datetime.now(timezone.utc)
            
            if success:
                # Update stats for successful attempt
                sync_db.execute(
                    """
                    UPDATE smtp_domain_stats 
                    SET 
                        total_attempts = total_attempts + 1,
                        successful_attempts = successful_attempts + 1,
                        success_rate = (successful_attempts + 1)::numeric / (total_attempts + 1),
                        avg_response_time_ms = CASE 
                            WHEN successful_attempts > 0 
                            THEN ((avg_response_time_ms * successful_attempts) + $1) / (successful_attempts + 1)
                            ELSE $2
                        END,
                        min_response_time_ms = CASE 
                            WHEN min_response_time_ms = 0 OR $3 < min_response_time_ms THEN $4
                            ELSE min_response_time_ms 
                        END,
                        max_response_time_ms = CASE 
                            WHEN max_response_time_ms < $5 THEN $6
                            ELSE max_response_time_ms 
                        END,
                        consecutive_failures = 0,
                        current_backoff_level = 0,
                        last_updated_at = $7,
                        last_success_at = $8
                    WHERE domain = $9
                    """,
                    response_time_ms, response_time_ms, response_time_ms, response_time_ms, 
                    response_time_ms, response_time_ms, current_time, current_time, domain
                )
            else:
                # Get current stats
                stats = self.get_domain_stats(domain)
                consecutive_failures = (stats.get('consecutive_failures', 0) or 0) + 1
                current_backoff_level = stats.get('current_backoff_level', 0) or 0
                
                # Implement exponential backoff for temporary failures
                if error_type == 'timeout' or (error_code and error_code in (421, 450, 451, 452)):
                    # Increase backoff level for temporary errors (max level 10)
                    new_backoff_level = min(current_backoff_level + 1, 10)
                    # Calculate backoff time using exponential formula (2^level seconds), max 24h
                    backoff_seconds = min(2 ** new_backoff_level, 86400)
                    retry_available_after = current_time + timedelta(seconds=backoff_seconds)
                    
                    # Update timeout adjustment factor (for adaptive timing)
                    previous_factor = stats.get('timeout_adjustment_factor', 1.0) or 1.0
                    # Convert Decimal to float before multiplication
                    if isinstance(previous_factor, decimal.Decimal):
                        previous_factor = float(previous_factor)
                    timeout_adjustment = min(previous_factor * 1.2, 3.0)
                else:
                    new_backoff_level = current_backoff_level
                    retry_available_after = None
                    timeout_adjustment = stats.get('timeout_adjustment_factor', 1.0) or 1.0
                
                # Mark domain as problematic if it fails consistently
                is_problematic = consecutive_failures >= 5
                
                # Update stats for failed attempt
                # Split into two separate SQL commands based on error_code
                if error_code is not None:
                    # With error code updating
                    sync_db.execute(
                        """
                        UPDATE smtp_domain_stats 
                        SET 
                            total_attempts = total_attempts + 1,
                            failed_attempts = failed_attempts + 1,
                            timeout_count = CASE WHEN $1 = 'timeout' THEN timeout_count + 1 ELSE timeout_count END,
                            success_rate = successful_attempts::numeric / (total_attempts + 1),
                            consecutive_failures = $2,
                            current_backoff_level = $3,
                            retry_available_after = $4,
                            timeout_adjustment_factor = $5,
                            last_updated_at = $6,
                            last_failure_at = $7,
                            is_problematic = $8,
                            last_error_code = $9,
                            common_error_codes = COALESCE(common_error_codes, '{}'::jsonb) || 
                                jsonb_build_object($10::text, COALESCE((common_error_codes->>$11::text)::int, 0) + 1)
                        WHERE domain = $12
                        """,
                        error_type, consecutive_failures, new_backoff_level, retry_available_after, 
                        timeout_adjustment, current_time, current_time, is_problematic, 
                        error_code, str(error_code), str(error_code), domain
                    )
                else:
                    # Without error code updating
                    sync_db.execute(
                        """
                        UPDATE smtp_domain_stats 
                        SET 
                            total_attempts = total_attempts + 1,
                            failed_attempts = failed_attempts + 1,
                            timeout_count = CASE WHEN $1 = 'timeout' THEN timeout_count + 1 ELSE timeout_count END,
                            success_rate = successful_attempts::numeric / (total_attempts + 1),
                            consecutive_failures = $2,
                            current_backoff_level = $3,
                            retry_available_after = $4,
                            timeout_adjustment_factor = $5,
                            last_updated_at = $6,
                            last_failure_at = $7,
                            is_problematic = $8
                        WHERE domain = $9
                        """,
                        error_type, consecutive_failures, new_backoff_level, retry_available_after, 
                        timeout_adjustment, current_time, current_time, is_problematic, domain
                    )
            
            # Record attempt history
            sync_db.execute(
                """
                INSERT INTO smtp_domain_attempt_history
                (domain, email, mx_host, port, attempt_time, response_time_ms, success, 
                error_code, error_type, trace_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                domain, '', mx_host or '', port or 0, current_time, response_time_ms, 
                success, error_code, error_type, trace_id
            )
            
        except Exception as e:
            logger.warning(f"Failed to update domain stats for {domain}: {e}")

    def check_retry_availability(self, domain: str) -> Tuple[bool, Optional[datetime]]:
        """Check if domain is available for retry based on backoff settings"""
        try:
            stats = self.get_domain_stats(domain)
            retry_after = stats.get('retry_available_after')
            
            if not retry_after:
                return True, None
                
            now = datetime.now(timezone.utc)
            if now < retry_after:
                return False, retry_after
                
            return True, None
            
        except Exception as e:
            logger.warning(f"Error checking retry availability for {domain}: {e}")
            return True, None

class DNSServerStats:
    """Manages DNS server statistics for performance monitoring and resolver selection"""
    
    def record_query_stats(self, nameserver: str, query_type: str, status: str, 
                     response_time_ms: Optional[float] = None, error_message: Optional[str] = None):
        """
        Record DNS query statistics
        
        Args:
            nameserver: The IP address of the nameserver used
            query_type: Type of DNS record queried (A, MX, TXT, etc.)
            status: 'success' or 'failure'
            response_time_ms: Query response time in milliseconds (for successful queries)
            error_message: Error message (for failed queries)
        """
        try:
            # Skip individual record insert and directly update aggregate stats
            if status == 'success':
                self._update_aggregate_stats(nameserver, query_type, True, response_time_ms)
            else:
                self._update_aggregate_stats(nameserver, query_type, False, None, error_message)
                
        except Exception as e:
            logger.warning(f"Failed to record DNS query stats for {nameserver}: {e}")
    
    def _update_aggregate_stats(self, nameserver: str, query_type: str, success: bool, 
                          response_time_ms: Optional[float] = None, error_message: Optional[str] = None):
        """
        Update aggregate statistics for a nameserver
        
        Args:
            nameserver: The IP address of the nameserver
            query_type: Type of DNS record queried
            success: Whether the query was successful
            response_time_ms: Query response time in milliseconds
            error_message: Error message (for failed queries)
        """
        try:
            current_time = datetime.now(timezone.utc)
            
            # Upsert the nameserver stats record
            if success:
                # For successful queries
                sync_db.execute(
                    """
                    INSERT INTO dns_server_stats 
                    (nameserver, query_type, queries, hits, 
                     avg_latency_ms, max_latency_ms, min_latency_ms, since, last_updated) 
                    VALUES 
                    ($1, $2, 1, 1, $3, $3, $3, $4, $4)
                    ON CONFLICT (nameserver, query_type) DO UPDATE SET
                        queries = dns_server_stats.queries + 1,
                        hits = dns_server_stats.hits + 1,
                        avg_latency_ms = (dns_server_stats.avg_latency_ms * 
                                         dns_server_stats.hits + $3) / 
                                         (dns_server_stats.hits + 1),
                        max_latency_ms = GREATEST(dns_server_stats.max_latency_ms, $3),
                        min_latency_ms = LEAST(
                            CASE WHEN dns_server_stats.min_latency_ms = 0 
                                 THEN $3 
                                 ELSE dns_server_stats.min_latency_ms END, 
                            $3),
                        last_updated = $4
                    """,
                    nameserver, query_type, response_time_ms, current_time
                )
            else:
                # For failed queries
                sync_db.execute(
                    """
                    INSERT INTO dns_server_stats 
                    (nameserver, query_type, queries, misses, errors, since, last_updated) 
                    VALUES 
                    ($1, $2, 1, 1, 1, $3, $3)
                    ON CONFLICT (nameserver, query_type) DO UPDATE SET
                        queries = dns_server_stats.queries + 1,
                        misses = dns_server_stats.misses + 1,
                        errors = dns_server_stats.errors + 1,
                        last_updated = $3
                    """,
                    nameserver, query_type, current_time
                )
                
        except Exception as e:
            logger.warning(f"Failed to update aggregate DNS stats for {nameserver}: {e}")
    
    def get_best_nameservers(self, count: int = 2, for_query_type: Optional[str] = None) -> List[str]:
        """
        Get the best performing nameservers based on response time and success rate
        
        Args:
            count: Number of nameservers to return
            for_query_type: If specified, get best nameservers for this query type
            
        Returns:
            List of nameserver IP addresses
        """
        try:
            query_condition = ""
            params: List[Any] = [count]
            
            if for_query_type:
                query_condition = "AND query_type = $2"
                params.append(for_query_type)
            
            # Get nameservers with highest success rate and lowest latency
            query = f"""
                SELECT 
                    nameserver,
                    SUM(hits) as success_count,
                    SUM(queries) as total_queries,
                    AVG(avg_latency_ms) as avg_latency
                FROM dns_server_stats
                WHERE last_updated > NOW() - INTERVAL '24 hours'
                {query_condition}
                GROUP BY nameserver
                HAVING SUM(queries) >= 5  -- Require minimum sample size
                ORDER BY 
                    (SUM(hits)::float / NULLIF(SUM(queries), 0)) DESC,
                    AVG(avg_latency_ms) ASC
                LIMIT $1
            """
            
            nameservers = sync_db.fetch(query, *params)
            
            # Extract just the IP addresses
            return [ns['nameserver'] for ns in nameservers]
    
        except Exception as e:
            logger.error(f"Failed to get best nameservers: {e}")
            return []
    
    def clean_up_old_stats(self, days: int = 30) -> int:
        """
        Clean up old DNS statistics records
        
        Args:
            days: Number of days of data to keep
            
        Returns:
            Number of records deleted
        """
        try:
            result = sync_db.execute(
                """
                DELETE FROM dns_server_stats
                WHERE last_updated < NOW() - INTERVAL '1 day' * $1
                RETURNING id
                """,
                days
            )
            
            count = len(result) if result else 0
            if count > 0:
                logger.info(f"Cleaned up {count} old DNS statistics records")
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to clean up DNS statistics: {e}")
            return 0
    
    def record_spf_statistics(self, trace_id, domain, result, mechanism_matched, dns_lookups, 
                         processing_time_ms, raw_record=None, explanation=None, 
                         error_message=None, dns_lookup_log=None):
        """
        Record SPF validation statistics
    
        Args:
            trace_id: Validation trace ID
            domain: The domain that was checked
            result: SPF result (pass, fail, softfail, neutral, none, permerror, temperror)
            mechanism_matched: The SPF mechanism that matched
            dns_lookups: Number of DNS lookups performed
            processing_time_ms: Processing time in milliseconds
            raw_record: Raw SPF record text
            explanation: Optional explanation text
            error_message: Optional error message
            dns_lookup_log: List of DNS lookup operations
        """
        try:
            # Insert main SPF validation statistics
            spf_validation_id = sync_db.fetchval(
                """
                INSERT INTO spf_validation_statistics 
                (trace_id, domain, raw_record, result, mechanism_matched, 
                 dns_lookups, processing_time_ms, explanation, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
                """,
                trace_id, domain, raw_record, result, mechanism_matched,
                dns_lookups, processing_time_ms, explanation, error_message
            )
            
            # Insert DNS lookup log entries if provided
            if dns_lookup_log and spf_validation_id:
                for entry in dns_lookup_log:
                    sync_db.execute(
                        """
                        INSERT INTO spf_dns_lookup_log
                        (spf_validation_id, mechanism, lookups_used, total_lookups)
                        VALUES ($1, $2, $3, $4)
                        """,
                        spf_validation_id, entry.get('mechanism'), 
                        entry.get('lookups_used', 0), entry.get('total_so_far', 0)
                    )
        
        except Exception as e:
            logger.error(f"Failed to record SPF statistics for {domain}: {str(e)}")
    
    def record_spf_dns_stats(self, domain: str, mechanism_type: str, 
                       lookups: int, success: bool, response_time_ms: Optional[float] = None):
        """
        Record SPF-specific DNS statistics
        
        Args:
            domain: The domain being queried
            mechanism_type: Type of SPF mechanism (a, mx, include, etc.)
            lookups: Number of lookups performed
            success: Whether the lookup was successful
            response_time_ms: Response time in milliseconds
        """
        try:
            current_time = datetime.now(timezone.utc)
            
            # Create aggregated statistics entry
            sync_db.execute(
                """
                INSERT INTO dns_server_stats 
                (nameserver, query_type, queries, hits, misses, errors, avg_latency_ms, 
                 max_latency_ms, min_latency_ms, since, last_updated) 
                VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (nameserver, query_type) DO UPDATE SET
                    queries = dns_server_stats.queries + $3,
                    hits = dns_server_stats.hits + $4,
                    misses = dns_server_stats.misses + $5,
                    errors = dns_server_stats.errors + $6,
                    avg_latency_ms = CASE 
                        WHEN $7 IS NOT NULL THEN 
                            (dns_server_stats.avg_latency_ms * dns_server_stats.hits + $7) / 
                            (dns_server_stats.hits + CASE WHEN $12 THEN 1 ELSE 0 END)
                        ELSE dns_server_stats.avg_latency_ms
                    END,
                    max_latency_ms = CASE 
                        WHEN $7 IS NOT NULL THEN GREATEST(dns_server_stats.max_latency_ms, $7) 
                        ELSE dns_server_stats.max_latency_ms
                    END,
                    min_latency_ms = CASE 
                        WHEN $7 IS NOT NULL THEN 
                            LEAST(
                                CASE WHEN dns_server_stats.min_latency_ms = 0 THEN $7 
                                     ELSE dns_server_stats.min_latency_ms END, 
                                $7
                            )
                        ELSE dns_server_stats.min_latency_ms
                    END,
                    last_updated = $11
                """,
                f"SPF:{domain}", f"mechanism:{mechanism_type}", 
                1,  # queries
                1 if success else 0,  # hits
                0 if success else 1,  # misses
                0 if success else 1,  # errors
                response_time_ms,  # avg_latency_ms
                response_time_ms,  # max_latency_ms
                response_time_ms,  # min_latency_ms
                current_time,  # since
                current_time,  # last_updated
                success  # for the CASE statement
            )
                    
        except Exception as e:
            logger.warning(f"Failed to update SPF DNS stats for {domain}/{mechanism_type}: {e}")

    def record_dmarc_statistics(self, trace_id: str, domain: str, result: str, 
                           policy_strength: str, dns_lookups: int, processing_time_ms: float,
                           raw_record: Optional[str] = None, has_reporting: bool = False,
                           alignment_mode: str = "relaxed", error_message: Optional[str] = None):
        """
        Record DMARC validation statistics
    
        Args:
            trace_id: Validation trace ID
            domain: The domain that was checked
            result: DMARC policy result (none, quarantine, reject)
            policy_strength: Policy strength assessment (none, weak, moderate, strong)
            dns_lookups: Number of DNS lookups performed
            processing_time_ms: Processing time in milliseconds
            raw_record: Raw DMARC record text
            has_reporting: Whether aggregate or forensic reporting is configured
            alignment_mode: Alignment mode (relaxed, strict)
            error_message: Optional error message
        """
        try:
            # Insert main DMARC validation statistics
            dmarc_validation_id = sync_db.fetchval(
                """
                INSERT INTO dmarc_validation_statistics 
                (trace_id, domain, raw_record, policy, policy_strength, 
                 dns_lookups, processing_time_ms, has_reporting, alignment_mode, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id
                """,
                trace_id, domain, raw_record, result, policy_strength,
                dns_lookups, processing_time_ms, has_reporting, alignment_mode, error_message
            )
            
            logger.debug(f"[{trace_id}] DMARC statistics recorded: domain={domain}, "
                        f"policy={result}, strength={policy_strength}, "
                        f"dns_lookups={dns_lookups}, time={processing_time_ms}ms")
    
        except Exception as e:
            logger.error(f"[{trace_id}] Failed to record DMARC statistics for {domain}: {str(e)}")

    def store_dmarc_analysis(self, domain: str, result: dict, trace_id: str):
        """
        Store DMARC analysis results for reporting and analytics
        
        Args:
            domain: The domain that was checked
            result: DMARC validation result object
            trace_id: Validation trace ID
        """
        try:
            # Check if the table exists before trying to insert
            table_check = sync_db.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'dmarc_validation_history'
                )
            """)
            
            if table_check and table_check[0][0]:  # Table exists
                import json
                from src.managers.time import now_utc
                
                sync_db.execute("""
                    INSERT INTO dmarc_validation_history 
                    (domain, policy, policy_strength, alignment_mode, percentage_covered,
                     aggregate_reporting, forensic_reporting, dns_lookups, processing_time_ms,
                     errors, warnings, recommendations, trace_id, validated_at, validation_date)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_DATE)
                    ON CONFLICT (domain, validation_date) 
                    DO UPDATE SET
                        policy = EXCLUDED.policy,
                        policy_strength = EXCLUDED.policy_strength,
                        last_validated_at = EXCLUDED.validated_at
                """,
                    domain, 
                    result.get('policy', 'none'), 
                    result.get('policy_strength', 'none'), 
                    result.get('alignment_mode', 'relaxed'),
                    result.get('percentage_covered', 0), 
                    result.get('aggregate_reporting', False), 
                    result.get('forensic_reporting', False),
                    result.get('dns_lookups', 0), 
                    result.get('execution_time_ms', 0),
                    json.dumps(result.get('errors', [])), 
                    json.dumps(result.get('warnings', [])), 
                    json.dumps(result.get('recommendations', [])), 
                    trace_id, 
                    now_utc()
                )
                logger.debug(f"[{trace_id}] DMARC analysis stored in database: {domain} -> {result.get('policy', 'none')}")
            else:
                # Table doesn't exist, just log the analysis
                logger.debug(f"[{trace_id}] DMARC analysis table not found: {domain} -> {result.get('policy', 'none')}")
                
        except Exception as e:
            logger.warning(f"[{trace_id}] Failed to store DMARC analysis: {e}")
