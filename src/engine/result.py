"""
Email Validation Result Models
===================================
Contains data structures for representing email validation results
"""

import uuid
import json
import dataclasses
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from src.managers.log import Axe, EMAIL, INFO, ERROR, DEBUG

# Initialize the logger with a more specific name
logger = Axe("email_validation")

__all__ = [
    'MxInfrastructure',
    'IpAddresses',
    'InfrastructureInfo', 
    'EmailValidationResult',
    'sanitize_value',
    'format_execution_time'
]

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
        
def sanitize_value(val):
    """Sanitize values for safe database storage"""
    if isinstance(val, list):
        return ",".join(str(x).replace(",", ";") for x in val)
    if isinstance(val, dict):
        return ",".join(f"{k}:{v}" for k, v in val.items())
    if val is None:
        return ""
    return str(val).replace("\n", " ").replace("\r", " ").replace(",", ";").replace('"', "'")

class EmailValidationResult:
    """Holds the results of email validation with structured data organization."""
    
    def __init__(self, email: str):
        # Log validation start
        logger.info(f"Starting validation for email: {email}")
        
        # Basic information
        self.email = email
        self.domain = email.split('@')[1] if '@' in email else ""
        self.trace_id: str = str(uuid.uuid4())
        self.batch_id = None
        self.span_id = ""
        
        # Log trace ID for correlation
        logger.debug(f"Validation trace ID: {self.trace_id} for {email}")
        
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
        
        # Detailed SPF information
        self.spf_details = {
            'valid': False,
            'record': '',
            'reason': '',
            'mechanism_matched': '',
            'dns_lookups': 0,
            'explanation': '',
            'domain': '',
            'execution_time': 0
        }
        
        # SMTP validation - update to include all required fields
        self.smtp_result = False      # Overall SMTP validation result
        self.smtp_banner = ''         # SMTP server banner
        self.smtp_vrfy = False        # VRFY command supported
        self.smtp_supports_tls = False # TLS supported
        self.smtp_supports_auth = False # AUTH supported
        self.smtp_flow_success = False # SMTP flow completed successfully
        self.smtp_error_code = None   # SMTP error code if any
        self.smtp_server_message = '' # SMTP server message
        self.connection_success = False
        
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
        
        # Log validation result
        validity_status = "valid" if self.is_valid else "invalid"
        confidence_info = f" (confidence: {self.confidence_level})" if self.confidence_level else ""
        logger.info(f"Email {self.email} validation completed: {validity_status}{confidence_info}")
        
        # If there was an error, log it
        if self.error_message:
            logger.error(f"Validation error for {self.email}: {self.error_message}")
        
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
            'spf_details': self.spf_details,
            
            # SMTP validation
            'smtp_result': self.smtp_result,
            'smtp_banner': str(self.smtp_banner),
            'smtp_vrfy': self.smtp_vrfy,
            'smtp_supports_tls': self.smtp_supports_tls,
            'smtp_supports_auth': self.smtp_supports_auth,
            'smtp_flow_success': self.smtp_flow_success,
            'smtp_error_code': self.smtp_error_code,
            'smtp_server_message': str(self.smtp_server_message),
            
            # Other validation results
            'is_disposable': self.is_disposable,
            'blacklist_info': self.blacklist_info,
            'catch_all': self.catch_all,
            'imap_status': self.imap_status,
            'imap_info': self.imap_info,
            'pop3_status': self.pop3_status,
            'pop3_info': self.pop3_info,
        }

    @staticmethod
    def log_to_batch_info(batch_id, name=None, source=None, status="processing", settings=None, 
                         total_emails=0, processed_emails=0, success_count=0, failed_count=0, 
                         error_message=None, completed=False) -> Optional[int]:
        """Log batch operation information to database."""
        # Log batch processing status
        logger.info(f"Batch {batch_id}: {status} - {processed_emails}/{total_emails} emails processed")
        
        if error_message:
            logger.error(f"Batch {batch_id} error: {error_message}")
            
        if completed:
            completion_msg = f"Batch {batch_id} completed - Success: {success_count}, Failed: {failed_count}"
            logger.info(completion_msg)
        
        from src.engine.database import log_batch_info
        return log_batch_info(
            batch_id, name, source, status, settings,
            total_emails, processed_emails, success_count, failed_count,
            error_message, completed
        )
        
    def finalize_validation(self):
        """Finalize the validation process and record execution time."""
        self.validation_complete = datetime.now()
        execution_time_ms = (self.validation_complete - self.validation_start).total_seconds() * 1000
        self.execution_time = execution_time_ms
        
        formatted_time = format_execution_time(execution_time_ms)
        logger.info(f"Validation for {self.email} completed in {formatted_time}")
        
        # Log detailed timings if available
        if self.timings:
            timing_details = ', '.join([f"{k}: {format_execution_time(v)}" for k, v in self.timings.items()])
            logger.debug(f"Timing breakdown for {self.email}: {timing_details}")
        
        return self
        
    def log_validation_step(self, step_name: str, success: bool = True, details: Optional[Dict] = None):
        """Log individual validation step."""
        status = "passed" if success else "failed"
        logger.debug(f"Validation step '{step_name}' {status} for {self.email}")
        
        if details and not success:
            logger.debug(f"Step '{step_name}' failure details: {json.dumps(details)}")
        
        return self
