"""
Email Verification Engine
=====================
Domain Information and Provider Detection Module

This module provides functionality to:
1. Extract email provider information from MX records
2. Update geographic information for domains
3. Detect email service providers based on MX patterns
4. Maintain provider mapping database
5. Extract organizational domains for DMARC/DKIM validation
"""

import re
from typing import Dict, Any, List, Optional, Set
from src.managers.log import get_logger
from src.helpers.dbh import sync_db
from src.managers.cache import cache_manager

# Initialize logging
logger = get_logger()

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
    
    # Known public domain services where subdomains are organizational domains
    PUBLIC_SERVICES = {
        'github.io': 3,      # user.github.io
        'herokuapp.com': 3,  # app.herokuapp.com
        'azurewebsites.net': 3,  # app.azurewebsites.net
        'appspot.com': 3,    # app.appspot.com
        'cloudfront.net': 3, # distribution.cloudfront.net
        'amazonaws.com': 3,  # bucket.s3.amazonaws.com (simplified)
        'netlify.app': 3,    # site.netlify.app
        'vercel.app': 3,     # app.vercel.app
        'surge.sh': 3,       # site.surge.sh
        'now.sh': 3,         # app.now.sh
        'firebaseapp.com': 3 # app.firebaseapp.com
    }
    
    def __init__(self):
        """Initialize the domain info extractor with PSL cache"""
        self._psl_cache = set()  # Initialize as an empty set to match return type
        self._psl_loaded = False
        
        # Fallback multi-part TLDs (used if database lookup fails)
        self._fallback_tlds = {
            'co.uk', 'org.uk', 'com.au', 'co.nz', 'co.jp', 'co.kr', 
            'co.in', 'co.za', 'com.br', 'com.mx', 'com.ar', 'com.co',
            'org.pl', 'com.sg'
        }

    def _load_public_suffix_list(self) -> Set[str]:
        """
        Load the Public Suffix List from the database with caching
        
        Returns:
            Set of public suffixes
        """
        # Check if already loaded in memory
        if self._psl_loaded and self._psl_cache:
            return self._psl_cache
            
        # Try to get from cache first
        cache_key = "public_suffix_list:all"
        cached_suffixes = cache_manager.get(cache_key)
        if cached_suffixes:
            self._psl_cache = cached_suffixes
            self._psl_loaded = True
            logger.debug(f"Loaded {len(cached_suffixes)} public suffixes from cache")
            return cached_suffixes
        
        # If not in cache, load from database
        try:
            suffixes = set()
            
            # Query all suffixes from database
            results = sync_db.fetch(
                """
                SELECT suffix, is_wildcard, is_exception
                FROM public_suffix_list
                """
            )
            
            for row in results:
                suffix = row['suffix']
                # Handle wildcard entries (like *.uk)
                if row['is_wildcard']:
                    # Store without the *. prefix for easier matching
                    suffix = suffix[2:] if suffix.startswith("*.") else suffix
                    
                # Exception rules are handled separately
                if not row['is_exception']:
                    suffixes.add(suffix)
            
            # Store in cache
            cache_manager.set(cache_key, suffixes, ttl=3600*24)  # 24 hours cache
            
            self._psl_cache = suffixes
            self._psl_loaded = True
            logger.info(f"Loaded {len(suffixes)} public suffixes from database")
            return suffixes
            
        except Exception as e:
            logger.warning(f"Failed to load public suffix list from database: {e}")
            self._psl_loaded = False
            return self._fallback_tlds

    def extract_organizational_domain(self, domain: str) -> str:
        """
        Extract the organizational domain for DMARC/DKIM purposes using Public Suffix List
        
        This method determines the organizational domain (the domain at which
        DMARC and DKIM policies should be published) according to RFC 7489.
        
        Examples:
        - mail.example.com → example.com
        - subdomain.example.co.uk → example.co.uk
        - app.github.io → app.github.io (special case)
        
        Args:
            domain: Full domain name
            
        Returns:
            Organizational domain suitable for DMARC/DKIM policy lookup
        """
        try:
            if not domain:
                return domain
                
            # Normalize domain
            domain = domain.lower().strip()
            parts = domain.split('.')
            
            if len(parts) < 2:
                return domain
            
            # Handle single-label domains (shouldn't happen in practice)
            if len(parts) == 1:
                return domain
            
            # Special handling for public domain services
            special_domain = self._get_special_domain_rules(domain, parts)
            if special_domain:
                return special_domain
                
            # Load public suffix list if needed
            public_suffixes = self._load_public_suffix_list()
            
            # Iterate through the domain parts to find matching TLD
            for i in range(len(parts)):
                # Try increasingly longer suffix combinations
                potential_suffix = '.'.join(parts[i:])
                if potential_suffix in public_suffixes:
                    # If we found a match and there's at least one label before it
                    if i > 0:
                        # Return the registrable domain (domain + public suffix)
                        return '.'.join(parts[i-1:])
            
            # Default case: return domain.tld format (last two parts)
            return '.'.join(parts[-2:])
            
        except Exception as e:
            logger.warning(f"Error extracting organizational domain from {domain}: {e}")
            return domain
    
    def _get_special_domain_rules(self, domain: str, parts: List[str]) -> Optional[str]:
        """
        Handle special cases for public domain services where subdomains
        should be treated as organizational domains
        
        Examples:
        - user.github.io → user.github.io (not github.io)
        - app.herokuapp.com → app.herokuapp.com (not herokuapp.com)
        """
        # Check if domain matches a public service pattern
        if len(parts) >= 3:
            service_domain = '.'.join(parts[-2:])  # e.g., github.io
            if service_domain in self.PUBLIC_SERVICES:
                required_parts = self.PUBLIC_SERVICES[service_domain]
                if len(parts) >= required_parts:
                    return '.'.join(parts[-(required_parts):])
        
        return None
    
    def update_geographic_info(self, domain: str, country_code=None, region=None, provider=None):
        """Update geographic information for a domain"""
        # Method implementation remains unchanged
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
        """Extract provider information from MX records"""
        # Method implementation remains unchanged
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
        """Detect email provider from MX hostname"""
        # Method implementation remains unchanged
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