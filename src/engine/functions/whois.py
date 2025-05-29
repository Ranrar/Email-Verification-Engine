"""
Email Verification Engine
=====================
Domain Information and Provider Detection Module

This module provides functionality to:
1. Extract email provider information from MX records
2. Update geographic information for domains
3. Detect email service providers based on MX patterns
4. Maintain provider mapping database
"""

import re
from typing import Dict, Any, List, Optional
from src.managers.log import Axe
from src.helpers.dbh import sync_db

# Initialize logging
logger = Axe()

class DomainInfoExtractor:
    """Extracts and manages domain provider information"""
    
    # Common email provider patterns
    PROVIDER_PATTERNS = {
        'google': r'(google|gmail|googlemail)\.com',
        'microsoft': r'(outlook|hotmail|live|msn|microsoft)\.com',
        'yahoo': r'(yahoo|ymail)\.com',
        'protonmail': r'(proton|protonmail)\.com',
        'zoho': r'zoho\.com',
        'aol': r'aol\.com',
        'fastmail': r'fastmail\.(com|fm)',
        'apple': r'(apple|icloud)\.com',
        'yandex': r'yandex\.(com|ru)',
        'mail.ru': r'mail\.ru'
    }
    
    def update_geographic_info(self, domain: str, country_code=None, region=None, provider=None):
        """Update geographic information for a domain"""
        if not (country_code or region or provider):
            return
        
        try:
            updates = []
            params = []
            param_index = 1  # Start with $1
            
            if country_code:
                updates.append(f"country_code = ${param_index}")
                params.append(country_code)
                param_index += 1
                
            if region:
                updates.append(f"region = ${param_index}")
                params.append(region)
                param_index += 1
                
            if provider:
                updates.append(f"detected_provider = ${param_index}")
                params.append(provider)
                param_index += 1
                
            if updates:
                params.append(domain)
                sync_db.execute(
                    f"""
                    UPDATE smtp_domain_stats 
                    SET {", ".join(updates)}
                    WHERE domain = ${param_index}
                    """,
                    *params  # Unpack the params with * operator
                )
        except Exception as e:
            logger.warning(f"Failed to update geographic info for {domain}: {e}")
    
    def extract_provider_info(self, mx_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract provider information from MX records
        
        Args:
            mx_records: List of MX record dictionaries with 'exchange' field
            
        Returns:
            Dictionary with provider information
        """
        result = {
            'provider': None,
            'is_custom_domain': True,
            'providers_detected': []
        }
        
        if not mx_records:
            return result
            
        # Check each MX record for known providers
        for mx in mx_records:
            mx_host = mx.get('exchange', '').lower()
            if not mx_host:
                continue
                
            provider = self.detect_provider_from_mx(mx_host)
            if provider and provider not in result['providers_detected']:
                result['providers_detected'].append(provider)
        
        # If we found any providers, use the first one as the main provider
        if result['providers_detected']:
            result['provider'] = result['providers_detected'][0]
            result['is_custom_domain'] = False
            
        return result
    
    def detect_provider_from_mx(self, mx_host: str) -> Optional[str]:
        """
        Detect email provider from MX hostname
        
        Args:
            mx_host: MX server hostname
            
        Returns:
            Provider name if detected, None otherwise
        """
        mx_host = mx_host.lower()
        
        # Check against known patterns
        for provider, pattern in self.PROVIDER_PATTERNS.items():
            if re.search(pattern, mx_host):
                return provider
                
        # Check for additional providers in database
        try:
            result = sync_db.fetchrow(
                """
                SELECT provider_name FROM email_providers
                WHERE $1 ~ mx_pattern
                ORDER BY priority DESC
                LIMIT 1
                """,
                mx_host
            )
            
            if result:
                return result['provider_name']
        except Exception as e:
            logger.warning(f"Error detecting provider from database: {e}")
            
        return None
        
def _extract_geographic_info(validator, context: Dict[str, Any], domain: str, mx_records: List[Dict[str, Any]]) -> None:
    """Extract and update geographic information from MX records"""
    # Type checking using runtime isinstance instead of static typing
    from src.engine.functions.smtp import SMTPValidator
    
    if not isinstance(validator, SMTPValidator):
        logger.warning(f"Expected SMTPValidator but got {type(validator)}")
        
    if 'mx_records_result' in context and isinstance(context['mx_records_result'], dict):
        mx_result = context['mx_records_result']
        
        # Extract geographic data from MX infrastructure
        infra_info = mx_result.get('infrastructure_info', {})
        if infra_info:
            country_code = None
            region = None
            provider = None
            
            # Get primary country code
            if infra_info.get('countries') and len(infra_info['countries']) > 0:
                country_code = infra_info['countries'][0]
                
            # Get provider info
            provider_info = validator.domain_info.extract_provider_info(mx_records)
            if provider_info and provider_info.get('provider'):
                provider = provider_info['provider']
            
            # Update domain stats with this geographic info
            validator.domain_info.update_geographic_info(domain, country_code, region, provider)