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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

# Import from refactored modules
from src.managers.log import Axe
from src.managers.cache import cache_manager, CacheKeys
from src.engine.result import EmailValidationResult
from src.engine.process import process_validation_results
from src.engine.database import log_to_database, log_validation_operation

logger = Axe()

# Global engine instance
_engine_instance = None

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
        db_record_id = log_to_database(result)
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
    
    # Log SMTP details - always log them regardless of result
    # Remove the condition that checks for result.smtp_details
    smtp_success = "✓" if result.smtp_result else "✗"
    smtp_banner = str(result.smtp_banner)
    smtp_code = result.smtp_error_code if result.smtp_error_code is not None else 'N/A'
    logger.debug(f"[{trace_id}] SMTP details: {smtp_success} Banner: {smtp_banner}, Code: {smtp_code}")

    # Log SMTP fields that will be stored in database
    db_fields = [
        f"smtp_result: {result.smtp_result}",
        f"smtp_banner: {str(result.smtp_banner)}",
        f"smtp_vrfy: {result.smtp_vrfy}",
        f"smtp_supports_tls: {result.smtp_supports_tls}",
        f"smtp_supports_auth: {result.smtp_supports_auth}",
        f"smtp_flow_success: {result.smtp_flow_success}",
        f"smtp_error_code: {result.smtp_error_code if result.smtp_error_code is not None else 'NULL'}",
        f"smtp_server_message: {str(result.smtp_server_message)}"
    ]
    logger.debug(f"[{trace_id}] SMTP DB fields: {', '.join(db_fields)}")
    
    return result.to_dict()

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

def get_engine(config: Optional[Dict] = None):
    """
    Get singleton instance of the email validation engine
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        EmailValidationEngine instance
    """
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = EmailValidationEngine()
    return _engine_instance