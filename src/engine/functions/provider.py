"""
Email Verification Engine - Provider Information
===============================================
Functions for identifying and analyzing email providers
"""

import re
import logging
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
from src.helpers.tracer import trace_function, ensure_trace_id, validate_trace_id

logger = logging.getLogger(__name__)

@dataclass
class ProviderInfo:
    """Email provider information structure"""
    name: str
    type: str  # 'corporate', 'freemail', 'education', 'government', 'custom'
    category: str  # 'major', 'regional', 'niche', 'temporary', 'suspicious'
    domain: str
    parent_company: Optional[str] = None
    country: Optional[str] = None
    supports_plus_addressing: bool = False
    supports_subdomain_addressing: bool = False
    common_aliases: Optional[List[str]] = None
    security_features: Optional[List[str]] = None
    reputation_score: int = 100  # 0-100, 100 being best
    risk_level: str = "low"  # 'low', 'medium', 'high', 'very_high'
    notes: Optional[str] = None

    def get(self, key, default=None):
        """
        Dictionary-like get method for ProviderInfo objects
        """
        return getattr(self, key, default)

# Comprehensive provider database
EMAIL_PROVIDERS = {
    # Major providers
    "gmail.com": ProviderInfo(
        name="Gmail",
        type="freemail",
        category="major", 
        domain="gmail.com",
        parent_company="Google",
        country="US",
        supports_plus_addressing=True,
        supports_subdomain_addressing=False,
        common_aliases=["googlemail.com"],
        security_features=["2FA", "OAuth", "Advanced Protection"],
        reputation_score=95,
        risk_level="low"
    ),
    "googlemail.com": ProviderInfo(
        name="Gmail",
        type="freemail",
        category="major",
        domain="googlemail.com",
        parent_company="Google",
        country="US",
        supports_plus_addressing=True,
        common_aliases=["gmail.com"],
        security_features=["2FA", "OAuth", "Advanced Protection"],
        reputation_score=95,
        risk_level="low"
    ),
    "outlook.com": ProviderInfo(
        name="Outlook.com",
        type="freemail",
        category="major",
        domain="outlook.com",
        parent_company="Microsoft",
        country="US",
        supports_plus_addressing=True,
        common_aliases=["hotmail.com", "live.com", "msn.com"],
        security_features=["2FA", "OAuth", "Advanced Threat Protection"],
        reputation_score=90,
        risk_level="low"
    ),
    "hotmail.com": ProviderInfo(
        name="Hotmail",
        type="freemail",
        category="major",
        domain="hotmail.com",
        parent_company="Microsoft",
        country="US",
        supports_plus_addressing=True,
        common_aliases=["outlook.com", "live.com"],
        security_features=["2FA", "OAuth"],
        reputation_score=85,
        risk_level="low"
    ),
    "yahoo.com": ProviderInfo(
        name="Yahoo Mail",
        type="freemail",
        category="major",
        domain="yahoo.com",
        parent_company="Verizon Media",
        country="US",
        supports_plus_addressing=True,
        common_aliases=["ymail.com", "rocketmail.com"],
        security_features=["2FA", "Account Key"],
        reputation_score=80,
        risk_level="low"
    ),
    "icloud.com": ProviderInfo(
        name="iCloud Mail",
        type="freemail",
        category="major",
        domain="icloud.com",
        parent_company="Apple",
        country="US",
        supports_plus_addressing=True,
        common_aliases=["me.com", "mac.com"],
        security_features=["2FA", "Hide My Email"],
        reputation_score=88,
        risk_level="low"
    ),
    
    # Corporate/Business providers
    "office365.com": ProviderInfo(
        name="Microsoft 365",
        type="corporate",
        category="major",
        domain="office365.com",
        parent_company="Microsoft",
        country="US",
        supports_plus_addressing=True,
        security_features=["Enterprise Security", "ATP", "DLP"],
        reputation_score=95,
        risk_level="low"
    ),
    "workspace.google.com": ProviderInfo(
        name="Google Workspace",
        type="corporate",
        category="major",
        domain="workspace.google.com",
        parent_company="Google",
        country="US",
        supports_plus_addressing=True,
        security_features=["Enterprise Security", "Vault", "DLP"],
        reputation_score=95,
        risk_level="low"
    ),
    
    # Temporary/Disposable email providers
    "10minutemail.com": ProviderInfo(
        name="10 Minute Mail",
        type="temporary",
        category="temporary",
        domain="10minutemail.com",
        reputation_score=10,
        risk_level="very_high",
        notes="Disposable email service"
    ),
    "guerrillamail.com": ProviderInfo(
        name="Guerrilla Mail",
        type="temporary", 
        category="temporary",
        domain="guerrillamail.com",
        reputation_score=15,
        risk_level="very_high",
        notes="Disposable email service"
    ),
    "mailinator.com": ProviderInfo(
        name="Mailinator",
        type="temporary",
        category="temporary", 
        domain="mailinator.com",
        reputation_score=20,
        risk_level="very_high",
        notes="Public inbox service"
    ),
    
    # Regional providers
    "mail.ru": ProviderInfo(
        name="Mail.Ru",
        type="freemail",
        category="regional",
        domain="mail.ru",
        parent_company="VK",
        country="RU",
        supports_plus_addressing=False,
        reputation_score=70,
        risk_level="medium"
    ),
    "yandex.ru": ProviderInfo(
        name="Yandex Mail",
        type="freemail",
        category="regional",
        domain="yandex.ru",
        parent_company="Yandex",
        country="RU",
        supports_plus_addressing=True,
        reputation_score=75,
        risk_level="medium"
    ),
    "163.com": ProviderInfo(
        name="NetEase Mail",
        type="freemail",
        category="regional",
        domain="163.com",
        parent_company="NetEase",
        country="CN",
        reputation_score=65,
        risk_level="medium"
    ),
    "qq.com": ProviderInfo(
        name="QQ Mail",
        type="freemail",
        category="regional",
        domain="qq.com",
        parent_company="Tencent",
        country="CN",
        reputation_score=70,
        risk_level="medium"
    ),
}

# Common temporary/disposable email domains
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
    "throwaway.email", "temp-mail.org", "getairmail.com", "fakeinbox.com",
    "maildrop.cc", "sharklasers.com", "yopmail.com", "33mail.com",
    "emailondeck.com", "mytrashmail.com", "spamgourmet.com", "dispostable.com"
}

# Corporate email patterns
CORPORATE_PATTERNS = [
    r'.*\.gov$',           # Government domains
    r'.*\.edu$',           # Educational domains  
    r'.*\.ac\.[a-z]{2}$',  # Academic domains
    r'.*\.org$',           # Organization domains (many are corporate)
    r'.*\.mil$',           # Military domains
]

@trace_function("get_email_provider_info")
def get_email_provider_info(email: str, trace_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive information about an email provider
    
    Args:
        email: Email address to analyze
        trace_id: Trace ID for operation tracking
        
    Returns:
        Dict containing provider information and analysis
    """
    
    # Ensure we have a valid trace_id
    trace_id = ensure_trace_id(trace_id)
    
    if not validate_trace_id(trace_id):
        logger.warning(f"Invalid trace_id in _get_email_provider_info: {trace_id}")
        trace_id = ensure_trace_id()
    
    try:
        # Extract domain from email
        if '@' not in email:
            logger.error(f"[{trace_id}] Invalid email format: {email}")
            return _create_error_response("Invalid email format", trace_id)
        
        domain = email.split('@')[1].lower().strip()
        
        logger.debug(f"[{trace_id}] Analyzing provider for domain: {domain}")
        
        # Initialize result structure
        result = {
            "domain": domain,
            "email": email,
            "trace_id": trace_id,
            "provider_found": False,
            "provider_info": None,
            "risk_assessment": {},
            "recommendations": [],
            "analysis": {}
        }
        
        # Check if domain is in our known providers database
        provider_info = EMAIL_PROVIDERS.get(domain)
        
        if provider_info:
            result["provider_found"] = True
            result["provider_info"] = {
                "name": provider_info.name,
                "type": provider_info.type,
                "category": provider_info.category,
                "domain": provider_info.domain,
                "parent_company": provider_info.parent_company,
                "country": provider_info.country,
                "supports_plus_addressing": provider_info.supports_plus_addressing,
                "supports_subdomain_addressing": provider_info.supports_subdomain_addressing,
                "common_aliases": provider_info.common_aliases or [],
                "security_features": provider_info.security_features or [],
                "reputation_score": provider_info.reputation_score,
                "risk_level": provider_info.risk_level,
                "notes": provider_info.notes
            }
        else:
            # Analyze unknown domain
            provider_info = _analyze_unknown_domain(domain, trace_id)
            result["provider_info"] = provider_info
        
        # Perform risk assessment
        result["risk_assessment"] = _assess_provider_risk(domain, provider_info, trace_id)
        
        # Generate recommendations
        result["recommendations"] = _generate_provider_recommendations(domain, provider_info, trace_id)
        
        # Additional analysis
        result["analysis"] = _perform_provider_analysis(domain, email, provider_info, trace_id)
        
        logger.debug(f"[{trace_id}] Provider analysis completed for {domain}")
        return result
        
    except Exception as e:
        logger.error(f"[{trace_id}] Error in _get_email_provider_info: {str(e)}")
        return _create_error_response(f"Provider analysis failed: {str(e)}", trace_id)

@trace_function("analyze_unknown_domain")
def _analyze_unknown_domain(domain: str, trace_id: str) -> Dict[str, Any]:
    """Analyze an unknown domain to determine provider characteristics"""
    
    provider_info = {
        "name": f"Unknown Provider ({domain})",
        "type": "unknown",
        "category": "unknown",
        "domain": domain,
        "parent_company": None,
        "country": None,
        "supports_plus_addressing": False,
        "supports_subdomain_addressing": False,
        "common_aliases": [],
        "security_features": [],
        "reputation_score": 50,  # Neutral score for unknown
        "risk_level": "medium",
        "notes": "Unknown provider - requires manual verification"
    }
    
    # Check if it's a disposable domain
    if domain in DISPOSABLE_DOMAINS:
        provider_info.update({
            "type": "temporary",
            "category": "temporary",
            "reputation_score": 10,
            "risk_level": "very_high",
            "notes": "Known disposable email provider"
        })
        return provider_info
    
    # Check corporate patterns
    for pattern in CORPORATE_PATTERNS:
        if re.match(pattern, domain):
            provider_info.update({
                "type": "corporate",
                "category": "corporate",
                "reputation_score": 80,
                "risk_level": "low",
                "notes": f"Corporate domain matching pattern: {pattern}"
            })
            break
    
    # Check for common freemail indicators
    freemail_indicators = ['free', 'mail', 'email', 'post', 'web']
    if any(indicator in domain for indicator in freemail_indicators):
        provider_info.update({
            "type": "freemail",
            "category": "regional",
            "reputation_score": 60,
            "risk_level": "medium",
            "notes": "Appears to be a freemail provider"
        })
    
    logger.debug(f"[{trace_id}] Analyzed unknown domain {domain}: {provider_info['type']}")
    return provider_info

@trace_function("assess_provider_risk")
def _assess_provider_risk(domain: str, provider_info: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
    """Assess risk level for the email provider"""
    
    risk_factors = []
    risk_score = 0
    
    # Check if disposable
    if domain in DISPOSABLE_DOMAINS or provider_info.get("type") == "temporary":
        risk_factors.append("Disposable/temporary email provider")
        risk_score += 50
    
    # Check reputation score
    reputation = provider_info.get("reputation_score", 50)
    if reputation < 30:
        risk_factors.append("Low reputation score")
        risk_score += 30
    elif reputation < 60:
        risk_factors.append("Below average reputation") 
        risk_score += 15
    
    # Check for known security features
    security_features = provider_info.get("security_features", [])
    if not security_features:
        risk_factors.append("No known security features")
        risk_score += 10
    
    # Check provider type
    provider_type = provider_info.get("type", "unknown")
    if provider_type == "unknown":
        risk_factors.append("Unknown provider type")
        risk_score += 20
    
    # Determine overall risk level
    if risk_score >= 70:
        risk_level = "very_high"
    elif risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "reputation_score": reputation
    }

@trace_function("generate_provider_recommendations")
def _generate_provider_recommendations(domain: str, provider_info: Dict[str, Any], trace_id: str) -> List[str]:
    """Generate recommendations based on provider analysis"""
    
    recommendations = []
    
    provider_type = provider_info.get("type", "unknown")
    risk_level = provider_info.get("risk_level", "medium")
    
    # Risk-based recommendations
    if risk_level == "very_high":
        recommendations.extend([
            "REJECT: High-risk provider detected",
            "Consider blocking this domain",
            "Require additional verification if accepting"
        ])
    elif risk_level == "high":
        recommendations.extend([
            "CAUTION: Elevated risk provider",
            "Implement additional verification steps",
            "Monitor for suspicious activity"
        ])
    elif risk_level == "medium":
        recommendations.extend([
            "VERIFY: Standard verification recommended",
            "Monitor delivery rates"
        ])
    else:
        recommendations.append("ACCEPT: Low-risk provider")
    
    # Type-specific recommendations
    if provider_type == "temporary":
        recommendations.extend([
            "Block disposable email addresses",
            "Require email verification",
            "Consider alternative contact methods"
        ])
    elif provider_type == "corporate":
        recommendations.extend([
            "Higher trust level appropriate",
            "Good for B2B communications",
            "Lower spam risk"
        ])
    elif provider_type == "freemail":
        recommendations.extend([
            "Standard verification recommended",
            "Monitor for abuse patterns",
            "Consider rate limiting"
        ])
    
    # Feature-based recommendations
    if provider_info.get("supports_plus_addressing"):
        recommendations.append("Provider supports plus addressing (+)")
    
    return recommendations

@trace_function("perform_provider_analysis")
def _perform_provider_analysis(domain: str, email: str, provider_info: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
    """Perform additional analysis on the provider and email"""
    
    analysis = {
        "domain_age_check": "unknown",
        "mx_provider_match": "unknown", 
        "subdomain_analysis": {},
        "alias_detection": {},
        "pattern_analysis": {}
    }
    
    # Subdomain analysis
    domain_parts = domain.split('.')
    if len(domain_parts) > 2:
        analysis["subdomain_analysis"] = {
            "has_subdomain": True,
            "subdomain": '.'.join(domain_parts[:-2]),
            "root_domain": '.'.join(domain_parts[-2:]),
            "risk_note": "Subdomain usage may indicate custom setup"
        }
    else:
        analysis["subdomain_analysis"] = {
            "has_subdomain": False,
            "root_domain": domain
        }
    
    # Check for alias patterns
    local_part = email.split('@')[0]
    analysis["alias_detection"] = _analyze_email_aliases(local_part, provider_info, trace_id)
    
    # Pattern analysis
    analysis["pattern_analysis"] = _analyze_email_patterns(local_part, domain, trace_id)
    
    logger.debug(f"[{trace_id}] Additional analysis completed for {domain}")
    return analysis

@trace_function("analyze_email_aliases")
def _analyze_email_aliases(local_part: str, provider_info: Dict[str, Any], trace_id: str) -> Dict[str, Any]:
    """Analyze the local part for alias patterns"""
    
    alias_info = {
        "has_plus_alias": False,
        "plus_alias_part": None,
        "base_email": local_part,
        "alias_type": "none"
    }
    
    # Check for plus addressing
    if '+' in local_part and provider_info.get("supports_plus_addressing", False):
        parts = local_part.split('+', 1)
        alias_info.update({
            "has_plus_alias": True,
            "plus_alias_part": parts[1],
            "base_email": parts[0],
            "alias_type": "plus_addressing"
        })
    
    # Check for dot variations (Gmail style)
    if '.' in local_part and provider_info.get("domain") == "gmail.com":
        alias_info["alias_type"] = "dot_variation"
        alias_info["base_email"] = local_part.replace('.', '')
    
    return alias_info

@trace_function("analyze_email_patterns") 
def _analyze_email_patterns(local_part: str, domain: str, trace_id: str) -> Dict[str, Any]:
    """Analyze email patterns for suspicious indicators"""
    
    patterns = {
        "has_numbers": bool(re.search(r'\d', local_part)),
        "has_special_chars": bool(re.search(r'[^a-zA-Z0-9._+-]', local_part)),
        "length": len(local_part),
        "random_pattern": False,
        "suspicious_indicators": []
    }
    
    # Check for random patterns
    if len(local_part) > 15 and re.search(r'[0-9]{4,}', local_part):
        patterns["random_pattern"] = True
        patterns["suspicious_indicators"].append("Long numeric sequences")
    
    # Check for too short
    if len(local_part) < 3:
        patterns["suspicious_indicators"].append("Very short local part")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'^(test|demo|sample|example)',
        r'(noreply|no-reply|donotreply)',
        r'^[a-z]{1,2}[0-9]{5,}$',  # Single letter + many numbers
        r'^[0-9]+$'  # Only numbers
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, local_part, re.IGNORECASE):
            patterns["suspicious_indicators"].append(f"Matches pattern: {pattern}")
    
    return patterns

def _create_error_response(error_message: str, trace_id: str) -> Dict[str, Any]:
    """Create standardized error response"""
    return {
        "error": True,
        "error_message": error_message,
        "trace_id": trace_id,
        "provider_found": False,
        "provider_info": None,
        "risk_assessment": {"risk_level": "unknown", "risk_score": 0},
        "recommendations": ["Manual review required due to analysis error"],
        "analysis": {}
    }

# Export the main function
__all__ = ['get_email_provider_info']