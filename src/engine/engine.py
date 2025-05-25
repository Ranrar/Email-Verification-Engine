"""
Email Verification Engine
===================================
    Email (Validation engine)
    - Score calculation
    - Results generation
    - Batch vs. single processing decisions
        - Threading and parallel execution
    - Progress tracking and monitoring
    - Task management and job control
  
    Blacklist check
    - Is domain blacklisted
    - Is domain Whitelisted

    Disposable
    - Description: Indicates whether the email address is from a disposable known domain.
    - Values: true / false.
"""

import time
import uuid
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from src.managers.log import Axe
from src.helpers.dbh import sync_db
from src.managers.cache import cache_manager, CacheKeys
import dataclasses


logger = Axe()

@dataclasses.dataclass
class MxInfrastructure:
    """MX server infrastructure information"""
    primary: Dict[str, Any] = dataclasses.field(default_factory=dict)
    backups: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    load_balanced: bool = False
    has_failover: bool = False
    used_fallback: bool = False

@dataclasses.dataclass
class IpAddresses:
    """IP addresses for mail servers"""
    ipv4: List[str] = dataclasses.field(default_factory=list)
    ipv6: List[str] = dataclasses.field(default_factory=list)
    geo: Dict[str, Any] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class InfrastructureInfo:
    """Email infrastructure information"""
    providers: List[str] = dataclasses.field(default_factory=list)
    countries: List[str] = dataclasses.field(default_factory=list)
    ptr_records: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    whois_data: Dict[str, Any] = dataclasses.field(default_factory=dict)

def format_execution_time(milliseconds):
    """Format execution time from milliseconds to a readable format like '2 minutes, 3.45 seconds'"""
    seconds = milliseconds / 1000.0
    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60
    
    if minutes > 0:
        return f"{minutes} minute{'s' if minutes > 1 else ''}, {remaining_seconds:.2f} seconds"
    else:
        return f"{remaining_seconds:.2f} seconds"

class EmailValidationResult:
    """Holds the results of email validation with structured data organization."""
    
    def __init__(self, email: str):
        # Basic information
        self.email = email
        self.domain = email.split('@')[1] if '@' in email else ""
        self.trace_id: str = str(uuid.uuid4())
        self.batch_id = None
        self.span_id = ""
        
        # Timing information
        self.validation_start = datetime.now()
        self.validation_complete: Optional[datetime] = None
        self.execution_time: float = 0.0
        self.timings: Dict[str, float] = {}
        
        # Validation results
        self.is_valid = False
        self.is_format_valid = False
        self.error_message = ""
        self.check_count = 1
        
        # Confidence scoring
        self.confidence_score = 0
        self.confidence_level = ""
        
        # DNS information
        self.mx_records = []
        self.mx_preferences = []
        self.mx_ip = ""
        
        # Enhanced MX data (structured)
        self.mx_infrastructure = MxInfrastructure()
        self.mx_ip_addresses = IpAddresses()
        self.email_provider = {
            "provider_name": "Unknown",
            "self_hosted": False,
            "provider_detected": False
        }
        self.infrastructure_info = InfrastructureInfo()
        
        # Security information
        self.spf_status = ""
        self.dkim_status = ""
        self.dmarc_status = ""
        self.server_policies = {}
        
        # SMTP validation
        self.smtp_result = False
        self.smtp_details = {}
        
        # Other validation results
        self.is_disposable = []
        self.blacklist_info = {}
        self.catch_all = False
        self.imap_status = ""
        self.imap_info = {}
        self.pop3_status = ""
        self.pop3_info = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        # Convert dataclasses to dictionaries
        mx_infrastructure_dict = dataclasses.asdict(self.mx_infrastructure) if isinstance(self.mx_infrastructure, MxInfrastructure) else self.mx_infrastructure
        mx_ip_addresses_dict = dataclasses.asdict(self.mx_ip_addresses) if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses
        infrastructure_info_dict = dataclasses.asdict(self.infrastructure_info) if isinstance(self.infrastructure_info, InfrastructureInfo) else self.infrastructure_info
        
        return {
            # Basic information
            'email': self.email,
            'domain': self.domain,
            'trace_id': self.trace_id,
            'batch_id': self.batch_id,
            
            # Timing information
            'execution_time': self.execution_time,
            'execution_time_formatted': format_execution_time(self.execution_time),
            'timings': self.timings,
            
            # Validation results
            'is_valid': self.is_valid,
            'is_format_valid': self.is_format_valid,
            'error_message': self.error_message,
            'check_count': self.check_count,
            
            # Confidence scoring
            'confidence_score': self.confidence_score,
            'confidence_level': self.confidence_level,
            
            # DNS information
            'mx_records': self.mx_records,
            'mx_preferences': self.mx_preferences,
            'mx_ip': self.mx_ip,
            
            # Enhanced MX data
            'mx_infrastructure': mx_infrastructure_dict,
            'mx_ip_addresses': mx_ip_addresses_dict,
            'email_provider': self.email_provider,
            'infrastructure_info': infrastructure_info_dict,
            
            # Security information
            'spf_status': self.spf_status,
            'dkim_status': self.dkim_status,
            'dmarc_status': self.dmarc_status,
            'server_policies': str(self.server_policies),
            
            # SMTP validation
            'smtp_result': self.smtp_result,
            'smtp_details': self.smtp_details,
            
            # Other validation results
            'is_disposable': self.is_disposable,
            'blacklist_info': self.blacklist_info,
            'catch_all': self.catch_all,
            'imap_status': self.imap_status,
            'imap_info': self.imap_info,
            'pop3_status': self.pop3_status,
            'pop3_info': self.pop3_info,
        }
    
    def log_to_database(self) -> Optional[int]:
        """Log validation result to database with full schema and sanitization."""
        try:
            import json
            db = sync_db
            data = self.to_dict()

            # Add proper integer field type handling
            def to_int_or_none(value):
                if value is None or value == "":
                    return None
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return None
            
            # Prepare sanitized values
            values = {
                # Existing fields...
                "timestamp": datetime.now(timezone.utc),
                "email": sanitize_value(data.get("email")),
                "domain": sanitize_value(data.get("domain")),
                # Integer fields with proper conversion
                "confidence_score": to_int_or_none(data.get("confidence_score", 0)),
                "check_count": to_int_or_none(data.get("check_count", 1)),
                "batch_id": to_int_or_none(data.get("batch_id")),
                # Other fields...
                "execution_time": data.get("execution_time", 0.0),
                # Rest of existing values...
            }

            # Extract and organize database fields
            db_fields = self._prepare_db_fields(data)
            
            # Insert the main validation record
            record_id = self._insert_validation_record(db, db_fields)
            
            # Store related MX infrastructure data if available
            if record_id and self.mx_records and self.trace_id:
                self._store_mx_infrastructure(db, record_id)
                logger.debug(f"[{self.trace_id}] MX infrastructure data stored for {self.email}")
            
            # Log detailed information about what was stored
            mx_count = len(self.mx_records) if self.mx_records else 0
            ipv4_count = len(self.mx_ip_addresses.ipv4) if isinstance(self.mx_ip_addresses, IpAddresses) else len(self.mx_ip_addresses.get('ipv4', []))
            ipv6_count = len(self.mx_ip_addresses.ipv6) if isinstance(self.mx_ip_addresses, IpAddresses) else len(self.mx_ip_addresses.get('ipv6', []))
            
            logger.info(f"[{self.trace_id}] Database record created for {self.email}: "
                       f"ID={record_id}, MX={mx_count}, IPv4={ipv4_count}, IPv6={ipv6_count}")
            
            return record_id

        except Exception as e:
            logger.error(f"[{self.trace_id}] Failed to log validation result for {self.email}: {e}", exc_info=True)
            return None
    
    def _prepare_db_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare fields for database insertion with proper sanitization."""
        mx_infrastructure_dict = data.get('mx_infrastructure', {})
        email_provider_dict = data.get('email_provider', {})
           
        def to_int_or_none(value):
            if value is None or value == "":
                return None
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        
        return {
            "trace_id": self.trace_id,
            "timestamp": datetime.now(timezone.utc),
            "email": sanitize_value(data.get("email")),
            "domain": sanitize_value(data.get("domain")),
            "smtp_result": sanitize_value(data.get("smtp_result")),
            "smtp_banner": sanitize_value(data.get("smtp_details", {}).get("banner", "")),
            "smtp_vrfy": sanitize_value(data.get("smtp_details", {}).get("vrfy_supported", "")),
            "port": sanitize_value(data.get("smtp_details", {}).get("port", "")),
            "mx_records": sanitize_value(data.get("mx_records")),
            "mx_ip": sanitize_value(data.get("mx_ip")),
            "mx_preferences": sanitize_value(data.get("mx_preferences")),
            "mx_analysis": json.dumps(mx_infrastructure_dict) if mx_infrastructure_dict else None,
            "email_provider_info": json.dumps(email_provider_dict) if email_provider_dict else None,
            "reverse_dns": sanitize_value(data.get("infrastructure_info", {}).get("ptr_records")),
            "whois_info": sanitize_value(data.get("infrastructure_info", {}).get("whois_data")),
            "catch_all": sanitize_value(data.get("catch_all")),
            "imap_status": sanitize_value(data.get("imap_status")),
            "imap_info": sanitize_value(data.get("imap_info")),
            "imap_security": "",  # Add this field if available
            "pop3_status": sanitize_value(data.get("pop3_status")),
            "pop3_info": sanitize_value(data.get("pop3_info")),
            "pop3_security": "",  # Add this field if available
            "spf_status": sanitize_value(data.get("spf_status")),
            "dkim_status": sanitize_value(data.get("dkim_status")),
            "dmarc_status": sanitize_value(data.get("dmarc_status")),
            "server_policies": sanitize_value(data.get("server_policies")),
            "disposable": sanitize_value(data.get("is_disposable")),
            "blacklist_info": sanitize_value(data.get("blacklist_info")),
            "error_message": sanitize_value(data.get("error_message")),
            "confidence_score": data.get("confidence_score", 0),
            "execution_time": data.get("execution_time", 0.0),
            "timing_details": sanitize_value(data.get("timings")),
            "check_count": data.get("check_count", 1),
            "batch_id": to_int_or_none(data.get("batch_id")),
            "raw_result": json.dumps(data)
        }
    
    def _insert_validation_record(self, db, values: Dict[str, Any]) -> Optional[int]:
        """Insert the main validation record and return its ID."""
        columns = ", ".join(values.keys())
        placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
        
        # Use UPSERT pattern to handle duplicate emails
        sql = f"""
            INSERT INTO email_validation_records (
                {columns}
            ) VALUES (
                {placeholders}
            )
            ON CONFLICT (trace_id) 
            DO UPDATE SET 
                timestamp = EXCLUDED.timestamp,
                smtp_result = EXCLUDED.smtp_result,
                smtp_banner = EXCLUDED.smtp_banner,
                smtp_vrfy = EXCLUDED.smtp_vrfy,
                port = EXCLUDED.port,
                mx_records = EXCLUDED.mx_records,
                mx_ip = EXCLUDED.mx_ip,
                mx_preferences = EXCLUDED.mx_preferences,
                reverse_dns = EXCLUDED.reverse_dns,
                whois_info = EXCLUDED.whois_info,
                catch_all = EXCLUDED.catch_all,
                imap_status = EXCLUDED.imap_status,
                imap_info = EXCLUDED.imap_info,
                imap_security = EXCLUDED.imap_security,
                pop3_status = EXCLUDED.pop3_status,
                pop3_info = EXCLUDED.pop3_info,
                pop3_security = EXCLUDED.pop3_security,
                spf_status = EXCLUDED.spf_status,
                dkim_status = EXCLUDED.dkim_status,
                dmarc_status = EXCLUDED.dmarc_status,
                server_policies = EXCLUDED.server_policies,
                disposable = EXCLUDED.disposable,
                blacklist_info = EXCLUDED.blacklist_info,
                error_message = EXCLUDED.error_message,
                confidence_score = EXCLUDED.confidence_score,
                execution_time = EXCLUDED.execution_time,
                timing_details = EXCLUDED.timing_details,
                check_count = EXCLUDED.check_count,
                batch_id = EXCLUDED.batch_id,
                raw_result = EXCLUDED.raw_result
            RETURNING id
        """

        result = db.fetchrow(sql, *values.values())
        return result['id'] if result else None
    
    def _store_mx_infrastructure(self, db, record_id: int) -> None:
        """Store MX infrastructure data in dedicated tables."""
        try:
            # Store MX infrastructure data
            if isinstance(self.mx_infrastructure, MxInfrastructure) or self.mx_infrastructure:
                # Extract infrastructure data
                mx_data = self.mx_infrastructure
                primary_mx = mx_data.primary if isinstance(mx_data, MxInfrastructure) else mx_data.get('primary', {})
                has_failover = mx_data.has_failover if isinstance(mx_data, MxInfrastructure) else mx_data.get('has_failover', False)
                load_balanced = mx_data.load_balanced if isinstance(mx_data, MxInfrastructure) else mx_data.get('load_balanced', False)
                used_fallback = mx_data.used_fallback if isinstance(mx_data, MxInfrastructure) else mx_data.get('used_fallback', False)
                
                # Get provider information
                provider_name = self._get_provider_name(db)
                
                # Insert MX infrastructure record
                mx_infra_id = self._insert_mx_infrastructure(db, record_id, primary_mx, 
                                                            has_failover, load_balanced, 
                                                            provider_name, used_fallback)
                
                # Store IP addresses
                if mx_infra_id:
                    self._store_ip_addresses(db, mx_infra_id)
        except Exception as e:
            logger.warning(f"Failed to store MX infrastructure: {e}")
    
    def _get_provider_id(self, db) -> Optional[int]:
        """Get or create email provider ID."""
        try:
            provider_name = self.email_provider.get('provider_name') if self.email_provider else None
            if provider_name and provider_name != "Unknown":
                provider_result = db.fetchrow(
                    "SELECT id FROM email_providers WHERE name = $1",
                    provider_name
                )
                
                if provider_result:
                    return provider_result['id']
                    
                # Optionally create provider if not exists
                # This would need additional code
            return None
        except Exception as e:
            logger.warning(f"Failed to get provider ID: {e}")
            return None
    
    def _get_provider_name(self, db) -> Optional[str]:
        """Get provider name from email_provider info."""
        try:
            provider_name = self.email_provider.get('provider_name') if self.email_provider else None
            return provider_name if provider_name and provider_name != "Unknown" else None
        except Exception as e:
            logger.warning(f"Failed to get provider name: {e}")
            return None
    
    def _insert_mx_infrastructure(self, db, record_id: int, primary_mx: Dict, 
                            has_failover: bool, load_balanced: bool,
                            provider_name: Optional[str], is_fallback: bool) -> Optional[int]:
        """Insert MX infrastructure record and return its ID."""
        try:
            import json
            
            mx_infra_values = {
                "trace_id": self.trace_id,
                "email_validation_id": record_id,
                "domain": self.domain,
                "mx_record": self.mx_ip or (primary_mx.get('servers', [])[0] if primary_mx.get('servers') else ""),
                "is_primary": True,
                "preference": primary_mx.get('preference'),
                "has_failover": has_failover,
                "load_balanced": load_balanced,
                "provider_name": provider_name,
                "is_self_hosted": self.email_provider.get('self_hosted', False) if self.email_provider else False,
                "is_fallback": is_fallback,
                "ip_addresses": json.dumps(dataclasses.asdict(self.mx_ip_addresses) if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses),
                "ptr_records": json.dumps(self.infrastructure_info.ptr_records if isinstance(self.infrastructure_info, InfrastructureInfo) else self.infrastructure_info.get('ptr_records', [])),
                "geo_info": json.dumps(self.mx_ip_addresses.geo if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses.get('geo', {})),
                "whois_summary": json.dumps(self.infrastructure_info.whois_data if isinstance(self.infrastructure_info, InfrastructureInfo) else self.infrastructure_info.get('whois_data', {})),
            }
            
            mx_columns = ", ".join(mx_infra_values.keys())
            mx_placeholders = ", ".join([f"${i+1}" for i in range(len(mx_infra_values))])
            
            mx_infra_result = db.fetchrow(
                f"INSERT INTO mx_infrastructure ({mx_columns}) VALUES ({mx_placeholders}) RETURNING id",
                *mx_infra_values.values()
            )
            
            return mx_infra_result['id'] if mx_infra_result else None
        except Exception as e:
            logger.warning(f"Failed to insert MX infrastructure: {e}")
            return None
            
    def _store_ip_addresses(self, db, mx_infra_id: int) -> None:
        """Store IP address records."""
        self._store_ipv4_addresses(db, mx_infra_id)
        self._store_ipv6_addresses(db, mx_infra_id)
    
    def _store_ipv4_addresses(self, db, mx_infra_id: int) -> None:
        """Store IPv4 address records."""
        ipv4_list = self.mx_ip_addresses.ipv4 if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses.get('ipv4', [])
        for ip in ipv4_list:
            try:
                if not ip:
                    continue
                    
                # Get geo data if available
                geo_data = (self.mx_ip_addresses.geo if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses.get('geo', {})).get(ip, {})
                
                # Get PTR record if available
                ptr_records = self.infrastructure_info.ptr_records if isinstance(self.infrastructure_info, InfrastructureInfo) else self.infrastructure_info.get('ptr_records', [])
                ptr_record = next((r['ptr'] for r in ptr_records if r['ip'] == ip), None)
                
                ip_values = {
                    "trace_id": self.trace_id,
                    "mx_infrastructure_id": mx_infra_id,
                    "ip_address": ip,
                    "ip_version": 4,
                    "is_private": False,
                    "ptr_record": ptr_record,
                    "country_code": geo_data.get('country') if geo_data else None,
                    "region": geo_data.get('region') if geo_data else None,
                    "provider": geo_data.get('provider') if geo_data else None
                }
                
                ip_columns = ", ".join(ip_values.keys())
                ip_placeholders = ", ".join([f"${i+1}" for i in range(len(ip_values))])
                
                db.execute(
                    f"INSERT INTO mx_ip_addresses ({ip_columns}) VALUES ({ip_placeholders})",
                    *ip_values.values()
                )
            except Exception as e:
                logger.warning(f"Failed to store IPv4 address {ip}: {e}")
    
    def _store_ipv6_addresses(self, db, mx_infra_id: int) -> None:
        """Store IPv6 address records."""
        ipv6_list = self.mx_ip_addresses.ipv6 if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses.get('ipv6', [])
        for ip in ipv6_list:
            try:
                if not ip:
                    continue
                    
                # Get geo data if available
                geo_data = (self.mx_ip_addresses.geo if isinstance(self.mx_ip_addresses, IpAddresses) else self.mx_ip_addresses.get('geo', {})).get(ip, {})
                
                ip_values = {
                    "trace_id": self.trace_id,
                    "mx_infrastructure_id": mx_infra_id,
                    "ip_address": ip,
                    "ip_version": 6,
                    "is_private": False,
                    "ptr_record": None,
                    "country_code": geo_data.get('country') if geo_data else None,
                    "region": geo_data.get('region') if geo_data else None,
                    "provider": geo_data.get('provider') if geo_data else None
                }
                
                ip_columns = ", ".join(ip_values.keys())
                ip_placeholders = ", ".join([f"${i+1}" for i in range(len(ip_values))])
                
                db.execute(
                    f"INSERT INTO mx_ip_addresses ({ip_columns}) VALUES ({ip_placeholders})",
                    *ip_values.values()
                )
            except Exception as e:
                logger.warning(f"Failed to store IPv6 address {ip}: {e}")
    
    def log_validation_step(self, function_name: str, step_name: str, 
                          start_time: datetime, end_time: Optional[datetime], 
                          status: str, result: Any, errors: Optional[str] = None) -> bool:
        """Log a validation step to the database."""
        try:
            db = sync_db
            
            duration_ms = (end_time - start_time).total_seconds() * 1000 if end_time and start_time else None
            
            # Determine step order (could come from a lookup table or just use timestamp)
            step_order = int(start_time.timestamp() * 1000) if start_time else 0
            
            values = {
                "trace_id": self.trace_id,
                "email": self.email,
                "step_name": step_name,
                "function_name": function_name,
                "step_order": step_order,
                "start_time": start_time,
                "end_time": end_time,
                "duration_ms": duration_ms,
                "status": status,
                "is_success": status == "success",
                "result": json.dumps(result) if result else None,
                "errors": errors
            }
            
            columns = ", ".join(values.keys())
            placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
            
            db.execute(
                f"INSERT INTO validation_steps ({columns}) VALUES ({placeholders})",
                *values.values()
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to log validation step: {e}", exc_info=True)
            return False

    @staticmethod
    def log_to_batch_info(batch_id, name=None, source=None, status="processing", settings=None, 
                         total_emails=0, processed_emails=0, success_count=0, failed_count=0, 
                         error_message=None, completed=False) -> Optional[int]:
        """Log batch operation information to database."""
        try:
            db = sync_db
            
            # Prepare values
            now = datetime.now(timezone.utc)
            values = {
                "created_at": now,
                "batch_id": batch_id,
                "name": name or f"Batch {batch_id[:8]}",
                "source": source or "API",
                "completed_at": now if completed else None,
                "total_emails": total_emails,
                "processed_emails": processed_emails,
                "success_count": success_count,
                "failed_count": failed_count,
                "status": status,
                "error_message": error_message or "",
                "settings_snapshot": settings or {}
            }
            
            columns = ", ".join(values.keys())
            placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
            
            # Use UPSERT pattern for updating existing batch records
            sql = f"""
                INSERT INTO batch_info (
                    {columns}
                ) VALUES (
                    {placeholders}
                )
                ON CONFLICT (batch_id) 
                DO UPDATE SET 
                    name = EXCLUDED.name,
                    completed_at = EXCLUDED.completed_at,
                    total_emails = EXCLUDED.total_emails,
                    processed_emails = EXCLUDED.processed_emails,
                    success_count = EXCLUDED.success_count,
                    failed_count = EXCLUDED.failed_count,
                    status = EXCLUDED.status,
                    error_message = EXCLUDED.error_message
                RETURNING id
            """
            
            result = db.fetchrow(sql, *values.values())
            batch_record_id = result['id'] if result else None
            
            logger.info(f"Logged batch info for {batch_id} to database with ID {batch_record_id}")
            return batch_record_id
            
        except Exception as e:
            logger.error(f"Failed to log batch info for {batch_id}: {e}", exc_info=True)
            return None

# Add this function to track validation steps in the database
def log_validation_step(self, function_name, step_name, start_time, end_time, status, result, errors=None):
    """Log a validation step to the database."""
    try:
        db = sync_db
        
        duration_ms = (end_time - start_time).total_seconds() * 1000 if end_time and start_time else None
        
        # Determine step order (could come from a lookup table or just use timestamp)
        step_order = int(start_time.timestamp() * 1000) if start_time else 0
        
        values = {
            "trace_id": self.trace_id,
            "email": self.email,
            "step_name": step_name,
            "function_name": function_name,
            "step_order": step_order,
            "start_time": start_time,
            "end_time": end_time,
            "duration_ms": duration_ms,
            "status": status,
            "is_success": status == "success",
            "result": json.dumps(result) if result else None,
            "errors": errors
        }
        
        columns = ", ".join(values.keys())
        placeholders = ", ".join([f"${i+1}" for i in range(len(values))])
        
        db.execute(
            f"INSERT INTO validation_steps ({columns}) VALUES ({placeholders})",
            *values.values()
        )
        
        return True
    except Exception as e:
        logger.error(f"Failed to log validation step: {e}", exc_info=True)
        return False

def validate_email(email: str, trace_id: Optional[str] = None, use_cache: bool = True) -> Dict[str, Any]:
    """
    Validates a single email address using the dynamic validation queue.
    
    Args:
        email: The email address to validate
        trace_id: Optional trace ID for tracking the validation process
        use_cache: Whether to use cached results if available
        
    Returns:
        Dictionary with validation results
    """
    # Generate or use provided trace ID
    if not trace_id:
        trace_id = str(uuid.uuid4())
    
    logger.info(f"[{trace_id}] Starting validation for {email}")
    
    # Check cache for existing validation results
    if use_cache:
        cache_key = f"validation_result:{email}"
        cached_result, expiry_info = cache_manager.get_with_expiry(cache_key)
        
        if cached_result:
            # Calculate remaining TTL and add to result
            now = time.time()
            cached_result['cache_info'] = {
                'from_cache': True,
                'created_at': expiry_info.get('created_at', now),
                'expires_at': expiry_info.get('expires_at', now),
                'ttl_seconds': max(0, (expiry_info.get('expires_at') or now) - now),
                'cached_components': {}
            }
            
            # Add component-specific TTL info if available
            for component in ['format_check', 'mx_records', 'smtp_check', 'disposable_check']:
                comp_key = f"{component}:{email}"
                comp_result, comp_expiry = cache_manager.get_with_expiry(comp_key)
                if comp_result and comp_expiry:
                    cached_result['cache_info']['cached_components'][component] = {
                        'ttl_seconds': max(0, (comp_expiry.get('expires_at') or now) - now),
                        'expires_at': comp_expiry.get('expires_at', now)
                    }
            
            # Log cache usage with TTL information
            ttl_minutes = cached_result['cache_info']['ttl_seconds'] / 60
            logger.info(f"[{trace_id}] Using cached validation result for {email} (expires in {ttl_minutes:.1f} minutes)")
            
            for comp, info in cached_result['cache_info']['cached_components'].items():
                comp_ttl_minutes = info['ttl_seconds'] / 60
                logger.debug(f"[{trace_id}] Component {comp} cached (expires in {comp_ttl_minutes:.1f} minutes)")
            
            # Update the trace ID in the cached result
            cached_result['trace_id'] = trace_id
            return cached_result
    
    # Create a result object to hold validation results
    result = EmailValidationResult(email)
    result.trace_id = trace_id
    
    # Get validation queue instance
    from src.engine.queue import DynamicQueue
    validation_queue = DynamicQueue.get_instance()
    
    # Prepare context for validation functions
    context = {
        "email": email,
        "trace_id": result.trace_id,
        "track_steps": True  # Add flag to track steps
    }
    
    # Start validation timer
    result.validation_start = datetime.now()
    logger.debug(f"[{trace_id}] Validation process started for {email}")
    
    # Execute all validation functions in order through the queue
    logger.debug(f"[{trace_id}] Executing validation queue for {email}")
    validation_results = validation_queue.execute(context)
    
    # Mark validation complete
    result.validation_complete = datetime.now()
    result.execution_time = (result.validation_complete - result.validation_start).total_seconds() * 1000
    logger.debug(f"[{trace_id}] Validation completed for {email} in {result.execution_time:.2f}ms")
    
    # Process validation results
    logger.debug(f"[{trace_id}] Processing validation results for {email}")
    process_validation_results(result, validation_results)
    
    # Log result to database
    try:
        db_record_id = result.log_to_database()
        # Enhanced logging with validation results summary
        logger.info(f"[{trace_id}] Validation results for {email} uploaded to database. " 
                   f"Result: {'✓ Valid' if result.is_valid else '✗ Invalid'}, "
                   f"Score: {result.confidence_score}, Level: {result.confidence_level}, "
                   f"Record ID: {db_record_id}")
        
        # Add more detailed logging about specific checks
        validation_details = []
        if result.is_format_valid:
            validation_details.append("Format: ✓")
        if result.mx_records:
            validation_details.append(f"MX: ✓ ({len(result.mx_records)} records)")
        if result.smtp_result:
            validation_details.append("SMTP: ✓")
        if result.email_provider and result.email_provider.get('provider_name') != "Unknown":
            validation_details.append(f"Provider: {result.email_provider.get('provider_name')}")
            
        if validation_details:
            logger.info(f"[{trace_id}] Details: {', '.join(validation_details)}")
            
    except Exception as e:
        logger.error(f"[{trace_id}] Failed to log validation results to database for {email}: {e}")
        # Add more detailed error information
        logger.error(f"[{trace_id}] Database upload error details: {type(e).__name__}, {str(e)}")
        # Log stack trace at debug level
        logger.debug(f"[{trace_id}] Database error stack trace:", exc_info=True)
    
    # Cache the validation results
    if use_cache:
        # Calculate appropriate TTL based on confidence score
        # Higher confidence = longer TTL
        if result.confidence_score >= 90:
            ttl = 86400  # 24 hours for high confidence results
        elif result.confidence_score >= 70:
            ttl = 43200  # 12 hours
        elif result.confidence_score >= 50:
            ttl = 21600  # 6 hours
        else:
            ttl = 3600   # 1 hour for low confidence results
            
        cache_key = f"validation_result:{email}"
        result_dict = result.to_dict()
        cache_manager.set(cache_key, result_dict, ttl=ttl)
        logger.debug(f"[trace_id] Cached validation result for {email} with TTL {ttl}s")
    
    logger.info(f"[{trace_id}] Validation process completed for {email} with score {result.confidence_score}")
    return result.to_dict()

    # Getting resaults form functions

def process_validation_results(result: EmailValidationResult, validation_results: Dict[str, Any]) -> None:
    """Process validation results and update the EmailValidationResult object"""
    logger.debug(f"[{result.trace_id}] Processing validation results: {validation_results.keys()}")
    
    # Format check processing - look for both possible key names
    format_result = None
    if 'email_format_results' in validation_results:
        format_result = validation_results.get('email_format_results', {})
    elif 'email_format_resaults' in validation_results:  # Note the typo in 'resaults'
        format_result = validation_results.get('email_format_resaults', {})
    
    if format_result:
        result.is_format_valid = format_result.get('valid', False)
        logger.info(f"[{result.trace_id}] Format check result: {result.is_format_valid}")
    elif validation_results.get('valid') is not None:
        result.is_format_valid = validation_results.get('valid', False)
    else:
        result.is_format_valid = False
    
    # Enhanced MX records processing
    mx_check = validation_results.get('mx_records') or validation_results.get('check_mx_records', {})
    
    if isinstance(mx_check, dict):
        # Extract basic MX data (for backward compatibility)
        if 'records' in mx_check and mx_check['records']:
            result.mx_records = mx_check['records']
        elif 'mx_records' in mx_check:
            result.mx_records = mx_check['mx_records']
            
        if 'preferences' in mx_check:
            result.mx_preferences = mx_check['preferences']
        elif 'mx_preferences' in mx_check:
            result.mx_preferences = mx_check['mx_preferences']
            
        # Legacy MX IP field
        if 'mx_record' in mx_check:
            result.mx_ip = mx_check['mx_record']
        
        # Extract enhanced MX infrastructure data
        if 'mx_infrastructure' in mx_check:
            result.mx_infrastructure = mx_check['mx_infrastructure']
            
        # Extract IP address data
        if 'ip_addresses' in mx_check:
            result.mx_ip_addresses = mx_check['ip_addresses']
            # Also update the legacy mx_ip field for backward compatibility
            ipv4_list = mx_check['ip_addresses'].get('ipv4', [])
            if ipv4_list and not result.mx_ip:
                result.mx_ip = ipv4_list[0] if isinstance(ipv4_list, list) else str(ipv4_list)
        
        # Extract infrastructure info
        if 'infrastructure_info' in mx_check:
            result.infrastructure_info = mx_check['infrastructure_info']
            
        # Extract email provider info
        if 'email_provider' in mx_check:
            provider_data = mx_check['email_provider']
            # Only keep the fields we need
            result.email_provider = {
                "provider_name": provider_data.get('provider_name', "Unknown"),
                "self_hosted": provider_data.get('self_hosted', False),
                "provider_detected": provider_data.get('provider_name', "Unknown") != "Unknown"
            }
        
        # Log successful MX validation with enhanced data
        if mx_check.get('valid', False):
            logger.debug(f"[{result.trace_id}] MX records found: {len(result.mx_records)} records")
            if result.email_provider and result.email_provider.get('provider_detected'):
                logger.debug(f"[{result.trace_id}] Email provider: {result.email_provider.get('provider_name')}")
    
    if 'smtp_check' in validation_results:
        smtp_result = validation_results.get('smtp_check', {})
        result.smtp_result = smtp_result.get('valid', False)
        result.smtp_details = smtp_result
    
    if 'disposable_check' in validation_results:
        disposable_check = validation_results.get('disposable_check', {})
        result.is_disposable = disposable_check.get('is_disposable', False)
    
    if 'catch_all_check' in validation_results:
        catch_all = validation_results.get('catch_all_check', {})
        result.catch_all = catch_all.get('is_catch_all', False)
    
    if 'dns_security' in validation_results:
        dns_sec = validation_results.get('dns_security', {})
        result.spf_status = dns_sec.get('spf', "")
        result.dkim_status = dns_sec.get('dkim', "")
        result.dmarc_status = dns_sec.get('dmarc', "")
    
    # Calculate overall validity and confidence score
    calculate_validity_and_confidence(result, validation_results)

def calculate_validity_and_confidence(result: EmailValidationResult, validation_results: Dict[str, Any]) -> None:
    """Calculate overall validity and confidence score"""
    # Check if MX fallback was used
    used_fallback = False
    if isinstance(result.mx_infrastructure, MxInfrastructure):
        used_fallback = result.mx_infrastructure.used_fallback
    elif isinstance(result.mx_infrastructure, dict):
        used_fallback = result.mx_infrastructure.get('used_fallback', False)
    
    # Determine overall validity - require real MX records, not fallbacks
    result.is_valid = (
        result.is_format_valid and  # Must have valid format
        bool(result.mx_records) and # Must have MX records
        not used_fallback           # Must not be using fallback A records
    )
    
    # Calculate confidence score
    score = 0
    max_score = 0
    
    # Format validity (20%)
    if result.is_format_valid:
        score += 20
    max_score += 20
    
    # MX records (15%) - only count real MX records, not fallbacks
    if result.mx_records and not used_fallback:
        score += 15
    max_score += 15
    
    # SMTP validation (30%)
    if result.smtp_result:
        score += 30
    max_score += 30
    
    # Not disposable (15%)
    if not result.is_disposable:
        score += 15
    max_score += 15
    
    # Not catch-all (10%)
    if result.catch_all is False:  # Explicitly False, not None
        score += 10
    max_score += 10
    
    # DNS security (10%)
    security_score = 0
    if result.spf_status:
        security_score += 1
    if result.dkim_status:
        security_score += 1
    if result.dmarc_status:
        security_score += 1
    
    score += (security_score / 3) * 10
    max_score += 10
    
    # Calculate final percentage
    result.confidence_score = int((score / max_score * 100) if max_score > 0 else 0)
    
    # Set confidence level
    if result.confidence_score >= 90:
        result.confidence_level = "Very High"
    elif result.confidence_score >= 70:
        result.confidence_level = "High"
    elif result.confidence_score >= 50:
        result.confidence_level = "Medium"
    elif result.confidence_score >= 30:
        result.confidence_level = "Low"
    else:
        result.confidence_level = "Very Low"

# Global engine instance
_engine_instance = None

class EmailValidationEngine:
    """Main engine for email validation"""
    
    def __init__(self):
        logger.info("Initializing EmailValidationEngine")
        # Check if cache is initialized
        if not hasattr(cache_manager, 'mem_cache'):
            logger.warning("Cache manager not properly initialized, some features may be limited")
    
    def validate(self, email: str, trace_id: Optional[str] = None, use_cache: bool = True) -> Dict[str, Any]:
        """
        Validate a single email address
        
        Args:
            email: Email address to validate
            trace_id: Optional trace ID for tracking
            use_cache: Whether to use cached results
            
        Returns:
            Dictionary with validation results
        """
        return validate_email(email, trace_id, use_cache)
        
    def batch_validate(self, emails: list, trace_id_prefix: Optional[str] = None, batch_name: Optional[str] = None, source: Optional[str] = None) -> list:
        """
        Validate multiple email addresses
        
        Args:
            emails: List of email addresses to validate
            trace_id_prefix: Optional prefix for trace IDs
            batch_name: Optional name for the batch
            source: Optional source information
            
        Returns:
            List of dictionaries with validation results
        """
        batch_id = str(uuid.uuid4())
        email_count = len(emails)
        
        logger.info(f"[batch:{batch_id}] Starting batch validation of {email_count} emails")
        
        # Log batch start
        EmailValidationResult.log_to_batch_info(
            batch_id=batch_id,
            name=batch_name,
            source=source,
            status="processing",
            total_emails=email_count,
            processed_emails=0,
            success_count=0,
            failed_count=0
        )
        
        results = []
        success_count = 0
        failed_count = 0
        
        try:
            for i, email in enumerate(emails):
                # Generate unique trace ID for each email in batch
                email_trace_id = f"{trace_id_prefix or 'batch'}-{batch_id[:8]}-{i+1}"
                
                try:
                    result = self.validate(email, trace_id=email_trace_id)
                    result["batch_id"] = batch_id
                    results.append(result)
                    
                    if result.get("is_valid", False):
                        success_count += 1
                    else:
                        failed_count += 1
                        
                    # Update batch progress every 10 emails
                    if (i + 1) % 10 == 0 or i == email_count - 1:
                        EmailValidationResult.log_to_batch_info(
                            batch_id=batch_id,
                            status="processing",
                            processed_emails=i + 1,
                            success_count=success_count,
                            failed_count=failed_count
                        )
                        
                except Exception as e:
                    logger.error(f"Error validating email {email}: {str(e)}")
                    failed_count += 1
                    results.append({
                        "email": email,
                        "error": str(e),
                        "is_valid": False,
                        "batch_id": batch_id
                    })
                    
            # Mark batch as completed
            EmailValidationResult.log_to_batch_info(
                batch_id=batch_id,
                status="completed",
                processed_emails=email_count,
                success_count=success_count,
                failed_count=failed_count,
                completed=True
            )
            
        except Exception as e:
            # Log batch error
            error_message = f"Batch processing error: {str(e)}"
            logger.error(f"[batch:{batch_id}] {error_message}")
            
            EmailValidationResult.log_to_batch_info(
                batch_id=batch_id,
                status="failed",
                processed_emails=len(results),
                success_count=success_count,
                failed_count=failed_count,
                error_message=error_message,
                completed=True
            )
        
        logger.info(f"[batch:{batch_id}] Completed batch validation of {email_count} emails. Success: {success_count}, Failed: {failed_count}")
        return results

def get_engine():
    """Get singleton instance of the email validation engine"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = EmailValidationEngine()
    return _engine_instance
      
def sanitize_value(val):
    if isinstance(val, list):
        return ",".join(str(x).replace(",", ";") for x in val)
    if isinstance(val, dict):
        return ",".join(f"{k}:{v}" for k, v in val.items())
    if val is None:
        return ""
    return str(val).replace("\n", " ").replace("\r", " ").replace(",", ";").replace('"', "'")