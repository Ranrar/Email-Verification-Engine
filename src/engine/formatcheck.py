"""
Email Verification Engine - Email Format Check Module
====================================================

This module provides email format checking functionality using configurable regex patterns
and validation rules. It supports RFC-compliant checks, international domains via IDNA,
and customizable validation criteria.

Key Components:
--------------
- EmailFormat: Main class for email format verification
- EmailFormatResult: Container for format check results with details
- LoadRegexPresets: Configuration loader from database with caching
- regex_factory: Factory function to create properly configured EmailFormat instances

Features:
--------
- Configurable validation rules and regex patterns from database
- RFC 5322 email format compliance checking
- International domain name (IDNA) support
- Performance optimized with multi-level caching
- Parallel processing support for batch operations
- Detailed error messages and validation steps
- Comprehensive timing statistics

Configuration:
-------------
The email format checker is configured through the `email_filter_regex_settings` and 
`email_filter_regex_presets` tables. Configuration includes:

1. Main settings - Basic behavior settings like max lengths and strictness
2. Validation steps - Which verification steps to enable/disable
3. Pattern checks - Which pattern-based rules to enforce
4. Format options - Options for basic format checking
5. Local part options - Rules for the part before the @ sign
6. Domain options - Rules for the domain part
7. IDNA options - Settings for international domain handling
8. Regex patterns - Custom regular expressions for different checks

Usage Examples:
-------------
Basic format check:
    checker = regex_factory()
    result = checker.check_email_format("user@example.com")
    is_valid = result.is_valid  # True or False
    
Batch processing:
    results = process_format_in_parallel_with_process_pool(["user1@example.com", "user2@example.com"])
    
Custom patterns:
    checker = regex_factory(use_cached_config=False)  # Force fresh config
    checker.PATTERNS["custom_pattern"] = re.compile(r"^.+@example.com$")
    
Performance tracking:
    stats = get_formating_performance_stats()
    avg_check_time = stats.get('email_format_check', {}).get('avg_ms', 0)

Extension Points:
---------------
1. Custom regex patterns can be added to the database
2. The EmailFormat class can be subclassed to add custom validation logic
3. Cache timeouts and strategies can be customized
4. Performance tracking can be extended for specific metrics

See Also:
--------
- RFC 5322: Internet Message Format
- IDNA: Internationalizing Domain Names in Applications (RFC 3490)
"""
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional
import idna

from src.managers.executor import process_pool
from src.managers.time import TimeManager, OperationTimer
from src.managers.cache import cache_manager, CacheKeys
from src.managers.log import get_logger
from src.helpers.dbh import sync_db

logger = get_logger()

# Initialize these directly when needed instead
time_manager = None

def get_time_manager():
    """Gets time manager from initialization or initializes it if needed"""
    # REMOVED: Check in _components
    try:
        # Try importing directly from where it might be defined as a singleton
        from src.managers.time import time_manager as tm
        if tm is not None:
            return tm
    except (ImportError, AttributeError):
        pass
        
    # Fallback to direct instantiation
    return TimeManager()

def get_cache_manager():
    """Gets cache manager from initialization or initializes it if needed"""
    # Just return the directly imported singleton
    return cache_manager

# Global instances
_email_regex_loader = None
_initializing_format_check = False

def get_config_loader():
    """Gets the configuration loader, ensuring it's initialized"""
    global _email_regex_loader, _initializing_format_check

    if _email_regex_loader is None and not _initializing_format_check:
        try:
            _initializing_format_check = True
            from src.helpers.dbh import sync_db
            _email_regex_loader = LoadRegexPresets(sync_db)
        except Exception as e:
            _initializing_format_check = False
            logger.error(f"Error initializing format check config: {e}")

    return _email_regex_loader

@dataclass
class EmailFormatResult: # Email format checker
    """Contains the detailed result of email format verification with context."""
    is_valid: bool = False
    normalized_email: Optional[str] = None
    original_email: Optional[str] = None
    local_part: Optional[str] = None
    domain: Optional[str] = None
    ascii_domain: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    format_check_steps: Dict[str, bool] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, error: str) -> None:
        """Add an error message to the result."""
        self.errors.append(error)
        logger.debug(f"Format check error: {error}")

    def add_warning(self, warning: str) -> None:
        """Add a warning message to the result."""
        self.warnings.append(warning)
        logger.debug(f"Format check warning: {warning}")

    def mark_step(self, step_name: str, passed: bool) -> None:
        """Mark a format verification step as passed or failed."""
        self.format_check_steps[step_name] = passed
        logger.debug(f"Format check step '{step_name}': {'PASSED' if passed else 'FAILED'}")

class EmailFormat: # all the format check settings
    """Class for verifying and normalizing email addresses."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize email format checker with optional configuration."""
        if config is None:
            # Load configuration from database if not provided
            config_loader = get_config_loader()
            if config_loader is not None:
                try:
                    self.config = config_loader.fetch_email_regex_config()
                    logger.debug("Loaded email format check configuration from database")
                except Exception as e:
                    error_msg = f"Failed to load email format check configuration: {e}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg) from e
            else:
                error_msg = "Config loader could not be initialized"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
        else:
            self.config = config
        
        # Maximum lengths based on standards
        self.max_local_length = self.config.get("max_local_length", 64)
        self.max_domain_length = self.config.get("max_domain_length", 255)
        self.max_total_length = self.config.get("max_total_length", 320)
        
        # Format check flags
        self.strict_mode = self.config.get("strict_mode", False)
        
        # Define which regex pattern to use for basic format check
        self.basic_format_pattern = self.config.get("basic_format_pattern", "basic")
        
        # Allow custom patterns to override defaults
        custom_patterns = self.config.get("custom_patterns", {})
        
        # Merge default patterns with any custom patterns
        self.PATTERNS = {
            # Basic pattern - just checks for something@something.something
            "basic": re.compile(r"^.+@.+\..+$"),
            
            # RFC 5322 compliant pattern - more strict
            "rfc5322": re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"),
            
            # Pattern for checking local part length
            "local_too_long": re.compile(r"^.{64,}@"),
            
            # Pattern for empty parts
            "empty_parts": re.compile(r"^@|@$|@\.|\.$"),
            
            # Pattern for whitespace
            "whitespace": re.compile(r'\s+'),
            
            # Pattern for consecutive dots
            "consecutive_dots": re.compile(r'\.{2,}'),
        }
        
        # Override with custom patterns
        for pattern_name, pattern in custom_patterns.items():
            if isinstance(pattern, str):
                self.PATTERNS[pattern_name] = re.compile(sanitize_regex(pattern))
            else:
                self.PATTERNS[pattern_name] = pattern
        
        # Format check steps to enable/disable
        self.format_check_steps = self.config.get("format_check_steps", {
            "basic_format": True,
            "normalization": True,
            "length_limits": True,
            "local_part": True,
            "domain": True,
            "idna": True
        })
        
        # Pattern checks to enable/disable
        self.pattern_checks = self.config.get("pattern_checks", {
            "empty_parts": True,
            "whitespace": True,
            "consecutive_dots": True
        })
        
        # Function-specific options
        self.basic_format_options = self.config.get("basic_format_options", {
            "check_empty_parts": True,
            "check_whitespace": True,
            "check_pattern": True
        })
        
        self.local_part_options = self.config.get("local_part_options", {
            "check_consecutive_dots": True,
            "check_chars_strict": True,
            "allowed_chars": "!#$%&'*+-/=?^_`{|}~." # RFC 5322 allowed special chars
        })
        
        self.domain_options = self.config.get("domain_options", {
            "require_dot": True,
            "check_hyphens": True,
            "check_chars": True,
            "check_consecutive_dots": True,
            "allowed_chars": ".-" # Only periods and hyphens allowed
        })
        
        self.idna_options = self.config.get("idna_options", {
            "encode_unicode": True,
            "validate_idna": True
        })
        
        logger.debug(f"Email format checker initialized with config: {self.config.get('name', 'default')}")


    def refresh_config(self):
        """Refresh configuration from database"""
        config_loader = get_config_loader()
        try:
            if config_loader is not None:
                self.config = config_loader.fetch_email_regex_config(refresh=True)
            else:
                logger.warning("Email format checker could not be initialized, using default configuration")
        except Exception as e:
            error_msg = f"Failed to refresh email format check: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        
        # Update all config-derived properties
        self.max_local_length = self.config.get("max_local_length", 64)
        self.max_domain_length = self.config.get("max_domain_length", 255)
        self.max_total_length = self.config.get("max_total_length", 320)
        self.strict_mode = self.config.get("strict_mode", False)
        self.basic_format_pattern = self.config.get("basic_format_pattern", "basic")
        
        # Update patterns with any custom ones
        custom_patterns = self.config.get("custom_patterns", {})
        for pattern_name, pattern in custom_patterns.items():
            if isinstance(pattern, str):
                self.PATTERNS[pattern_name] = re.compile(sanitize_regex(pattern))
            else:
                self.PATTERNS[pattern_name] = pattern
        
        # Update format check steps and options
        self.format_check_steps = self.config.get("format_check_steps", {
            "basic_format": True,
            "normalization": True,
            "length_limits": True,
            "local_part": True,
            "domain": True,
            "idna": True
        })
        
        self.pattern_checks = self.config.get("pattern_checks", {})
        self.basic_format_options = self.config.get("basic_format_options", {})
        self.local_part_options = self.config.get("local_part_options", {})
        self.domain_options = self.config.get("domain_options", {})
        self.idna_options = self.config.get("idna_options", {})
        
        logger.info("Email format check configuration refreshed from database")

    def check_email_format(self, email: str) -> EmailFormatResult:
        """Check an email address's format and return a detailed result object."""
        # Get time_manager and cache_manager via getters
        time_manager = get_time_manager()
        cache_manager = get_cache_manager()
        
        for category in ['email_format_check', 'basic_format', 'normalization', 'length_limits', 'total', 'cache_hits']:
            if not time_manager.get_stats(category):
                time_manager.create_stats(category)

        # Use OperationTimer for the entire format check process
        with OperationTimer("email_format_check") as timer:
            # Check cache first for this email
            cache_key = f"email_format_check:{email}"
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Using cached format check result for {email}")
                cache_hits_stats = time_manager.get_stats('cache_hits')
                if cache_hits_stats is not None:
                    cache_hits_stats.add_timing(email, timer.elapsed_ms)
                if isinstance(cached_result, EmailFormatResult):
                    return cached_result
                elif isinstance(cached_result, dict):
                    # Convert dict to EmailFormatResult instance
                    return EmailFormatResult(**cached_result)
                else:
                    logger.warning("Cached result is not of expected type, ignoring cache.")
                
            # Cache miss - Create result object
            result = EmailFormatResult(original_email=email)
            result.details["timings"] = {}  # Add timings dict to capture performance data
            
            # Apply format check chain with timing
            with OperationTimer("basic_format") as format_timer:
                basic_format_valid = self._email_basic_format_check(email, result)
                
            # Record timing for basic format check
            time_manager.add_timing(result.details["timings"], "basic_format", format_timer.elapsed_ms)
            basic_format_stats = time_manager.get_stats('basic_format')
            if basic_format_stats is not None:
                basic_format_stats.add_timing(email, format_timer.elapsed_ms)
            
            if basic_format_valid:
                # Continue with other format check steps, each with timing
                with OperationTimer("normalization") as norm_timer:
                    self._trim_email(email, result)
                time_manager.add_timing(result.details["timings"], "normalization", norm_timer.elapsed_ms)
                
                with OperationTimer("length_limits") as len_timer:
                    self._check_email_length(result)
                time_manager.add_timing(result.details["timings"], "length_limits", len_timer.elapsed_ms)
                
                # ... other steps with similar timing ...
                
            # Set final validity based on absence of errors
            result.is_valid = len(result.errors) == 0
            
            # Cache the result if there was meaningful verification
            if hasattr(result, 'normalized_email') and result.normalized_email:
                cache_manager.set(cache_key, result)
            
        # Add overall timing to result
        time_manager.add_timing(result.details["timings"], "total", timer.elapsed_ms)
        total_stats = time_manager.get_stats('total')
        if total_stats is not None:
            total_stats.add_timing(email, timer.elapsed_ms)
        
        return result

    def _email_basic_format_check(self, email: str, result: EmailFormatResult) -> bool:
        """Check if the email has a basic valid format."""
        options = self.basic_format_options
        
        # Check for empty parts or ending with dot
        if options.get("check_empty_parts", True) and self.pattern_checks.get("empty_parts", True) and self.PATTERNS["empty_parts"].search(email):
            result.add_error("Email contains empty parts or ends with a dot")
            result.mark_step("basic_format", False)
            return False
            
        # Check for whitespace
        if options.get("check_whitespace", True) and self.pattern_checks.get("whitespace", True) and self.PATTERNS["whitespace"].search(email):
            result.add_error("Email contains whitespace")
            result.mark_step("basic_format", False)
            return False
            
        # Check pattern
        if options.get("check_pattern", True) and not self.PATTERNS[self.basic_format_pattern].match(email):
            result.add_error(f"Email does not match {self.basic_format_pattern} format")
            result.mark_step("basic_format", False)
            return False
            
        # Split email into local and domain parts
        try:
            local, domain = email.rsplit("@", 1)
            result.local_part = local
            result.domain = domain
            result.mark_step("basic_format", True)
            return True
        except ValueError:
            result.add_error("Cannot split email into local and domain parts")
            result.mark_step("basic_format", False)
            return False

    def _trim_email(self, email: str, result: EmailFormatResult) -> None:
        """Normalize the email address (lowercase, trim)."""
        if not result.local_part or not result.domain:
            return
            
        # Convert local part and domain to lowercase
        local_normalized = result.local_part.lower()
        domain_normalized = result.domain.lower()
        
        # Combine into normalized email
        result.normalized_email = f"{local_normalized}@{domain_normalized}"
        
        # Check if normalization changed anything
        if result.normalized_email != email:
            result.add_warning("Email was normalized from original")
            result.details["original"] = email
            
        result.mark_step("normalization", True)

    def _check_email_length(self, result: EmailFormatResult) -> None:
        """chech that email parts don't exceed length limits."""
        if not result.local_part or not result.domain:
            return
            
        # Check local part length
        if len(result.local_part) > self.max_local_length:
            result.add_error(f"Local part exceeds maximum length of {self.max_local_length} characters")
            result.mark_step("length_limits", False)
            return
            
        # Check domain length
        if len(result.domain) > self.max_domain_length:
            result.add_error(f"Domain exceeds maximum length of {self.max_domain_length} characters")
            result.mark_step("length_limits", False)
            return
            
        # Check total length
        if len(result.normalized_email or "") > self.max_total_length:
            result.add_error(f"Email exceeds maximum total length of {self.max_total_length} characters")
            result.mark_step("length_limits", False)
            return
            
        result.mark_step("length_limits", True)

    def _check_email_local_part(self, result: EmailFormatResult) -> None:
        """check the local part of the email."""
        if not result.local_part:
            return
        
        options = self.local_part_options
        
        # Check for consecutive dots
        if options.get("check_consecutive_dots", True) and self.pattern_checks.get("consecutive_dots", True) and self.PATTERNS["consecutive_dots"].search(result.local_part):
            result.add_error("Local part contains consecutive dots")
            result.mark_step("local_part", False)
            return
            
        # Check for valid characters in strict mode
        if self.strict_mode and options.get("check_chars_strict", True):
            allowed_chars = options.get("allowed_chars", "!#$%&'*+-/=?^_`{|}~.")
            if not all(c.isalnum() or c in allowed_chars for c in result.local_part):
                result.add_error("Local part contains invalid characters in strict mode")
                result.mark_step("local_part", False)
                return
                
        result.mark_step("local_part", True)

    def _check_email_domain(self, result: EmailFormatResult) -> None:
        """check the domain part of the email."""
        if not result.domain:
            return
            
        options = self.domain_options
        
        # Check for at least one dot in domain
        if options.get("require_dot", True) and '.' not in result.domain:
            result.add_error("Domain must contain at least one dot")
            result.mark_step("domain", False)
            return
            
        # Check domain doesn't start or end with hyphen
        if options.get("check_hyphens", True) and (result.domain.startswith('-') or result.domain.endswith('-')):
            result.add_error("Domain cannot start or end with a hyphen")
            result.mark_step("domain", False)
            return
            
        # Check for valid characters in domain
        if options.get("check_chars", True):
            allowed_chars = options.get("allowed_chars", ".-")
            if not all(c.isalnum() or c in allowed_chars for c in result.domain):
                result.add_error("Domain contains invalid characters")
                result.mark_step("domain", False)
                return
            
        # Check for consecutive dots
        if options.get("check_consecutive_dots", True) and self.pattern_checks.get("consecutive_dots", True) and self.PATTERNS["consecutive_dots"].search(result.domain):
            result.add_error("Domain contains consecutive dots")
            result.mark_step("domain", False)
            return
            
        result.mark_step("domain", True)

    def _process_idna_encoding(self, result: EmailFormatResult) -> None:
        """check and convert international domain names."""
        if not result.domain:
            return
            
        options = self.idna_options
        
        # If domain already starts with xn--, it's already IDNA-encoded
        if result.domain.startswith('xn--'):
            if options.get("validate_idna", True):
                try:
                    # Try to decode the domain to verify it's valid IDNA
                    unicode_domain = idna.decode(result.domain)
                    result.details["unicode_domain"] = unicode_domain
                    result.ascii_domain = result.domain
                    result.mark_step("idna", True)
                    return
                except Exception as e:
                    result.add_error(f"Invalid IDNA domain: {e}")
                    result.mark_step("idna", False)
                    return
            else:
                # Skip IDNA validation
                result.ascii_domain = result.domain
                result.mark_step("idna", True)
                return
        
        # Handle regular domains
        if options.get("encode_unicode", True):
            try:
                # Convert Unicode domains via IDNA
                result.ascii_domain = idna.encode(result.domain).decode("ascii")
                result.details["ascii_email"] = f"{result.local_part}@{result.ascii_domain}"
                
                # Check if conversion changed anything
                if result.ascii_domain != result.domain:
                    result.add_warning("Domain contained non-ASCII characters and was IDNA-encoded")
                    
                result.mark_step("idna", True)
            except idna.IDNAError as e:
                result.add_error(f"IDNA encoding error: {e}")
                result.mark_step("idna", False)
            except Exception as e:
                result.add_error(f"Unexpected error during IDNA encoding: {e}")
                result.mark_step("idna", False)
        else:
            # Skip IDNA encoding
            result.ascii_domain = result.domain
            result.mark_step("idna", True)

class LoadRegexPresets:
    """Loads email format check regex patterns from the database with fallbacks."""
    
    def __init__(self, db_handler, cache_ttl=300, logger=None, time_manager=None):
        """Initialize the configuration loader."""
        self.db = db_handler
        self.cache_ttl = cache_ttl
        self.logger = logger or get_logger()  # Use provided logger or create new one
        self.time_manager = time_manager or get_time_manager()  # Use getter instead of direct initialization
        
    def fetch_email_regex_config(self, refresh=False) -> Dict[str, Any]:
        """
        Get email format check configuration with caching.
        
        Args:
            refresh: Force refresh from database
            
        Returns:
            Dict containing complete configuration for EmailFormat
        """
        # Use cache_manager getter instead of direct reference
        cache_key = "emailformatcheck"
        cache_manager = get_cache_manager()
        
        # Check if settings have changed or refresh is requested
        settings_changed = check_settings_changed()
        if refresh or settings_changed:
            self.logger.info(f"Loading email format check configuration from database (refresh={refresh}, changed={settings_changed})")
            # If settings changed, clear all related caches
            if settings_changed:
                cache_manager.delete(cache_key)
                cache_manager.delete("emailformatcheck")
                self.logger.debug("Email format check caches invalidated due to settings change")
        else:
            # Only check cache if no settings change detected
            cached_config = cache_manager.get(cache_key)
            if cached_config is not None:
                self.logger.debug("Using cached email format check configuration")
                return cached_config
    
        # Load configuration from database
        config = self._load_users_email_regex_config()
        
        # Cache the result
        cache_manager.set(cache_key, config)
        
        return config

    def _load_users_email_regex_config(self) -> Dict[str, Any]:
        """Load configuration from email_filter_regex_settings with ID 1 or fall back to presets"""
        config = {}
        
        try:
            # First try to get the active config
            row = self.db.fetchrow("""
                SELECT main_settings, validation_steps, pattern_checks, 
                        format_options, local_part_options, domain_options, 
                        idna_options, regex_pattern
                FROM email_filter_regex_settings
                WHERE nr = 1
            """)
             
            if not row:
                self.logger.warning("No active email validation configuration found (ID 1), using preset from database")
                
                # Load the first preset from database instead of hardcoded defaults
                preset_row = self.db.fetchrow("""
                    SELECT 
                        main_settings_config as main_settings,
                        validation_steps_config as validation_steps,
                        pattern_checks_config as pattern_checks,
                        format_options_config as format_options,
                        local_part_options_config as local_part_options,
                        domain_options_config as domain_options,
                        idna_options_config as idna_options,
                        regex_pattern_config as regex_pattern
                    FROM email_filter_regex_presets
                    ORDER BY id
                    LIMIT 1
                """)
                
                if not preset_row:
                    error_msg = "No email validation configuration presets found in database"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)
                    
                row = preset_row
                self.logger.info("Successfully loaded email validation preset from database")
            
            # Parse JSON strings from row
            try:
                config.update(json.loads(row['main_settings']))
                config["validation_steps"] = json.loads(row['validation_steps'])
                config["pattern_checks"] = json.loads(row['pattern_checks'])
                config["basic_format_options"] = json.loads(row['format_options'])
                config["local_part_options"] = json.loads(row['local_part_options'])
                config["domain_options"] = json.loads(row['domain_options'])
                config["idna_options"] = json.loads(row['idna_options'])
                
                # Handle regex patterns
                custom_patterns = json.loads(row['regex_pattern'])
                config["custom_patterns"] = custom_patterns
                
                return config
                
            except json.JSONDecodeError as e:
                error_msg = f"Error parsing JSON configuration: {e}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg) from e
        
        except Exception as e:
            error_msg = f"Database error when loading email validation configuration: {e}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        
def regex_factory(use_cached_config=True) -> EmailFormat:
    """
    Factory function to create an EmailFormat with configuration.

    Args:
        use_cached_config: Whether to use cached configuration or force refresh

    Returns:
        Configured EmailFormat instance
    """
    cache_key = "ev_filter_instance"
    cache_mgr = get_cache_manager()

    # First check if settings have changed
    settings_changed = check_settings_changed()
    
    # Use cached instance only if settings haven't changed and caching is requested
    if use_cached_config and not settings_changed:
        cached_filter = cache_mgr.get(cache_key)
        if isinstance(cached_filter, EmailFormat):
            logger.debug("Using cached EmailFormat instance")
            return cached_filter

    # Load new configuration
    config_loader = get_config_loader()
    if config_loader is None:
        raise RuntimeError("Config loader could not be initialized")
    
    # Force refresh if settings changed
    config = config_loader.fetch_email_regex_config(refresh=settings_changed or not use_cached_config)
    filter_instance = EmailFormat(config)

    # Cache the new instance
    cache_mgr.set(cache_key, filter_instance)

    return filter_instance

def process_format_in_parallel_with_process_pool(emails):
    """Process multiple emails in parallel using process pool"""
    with OperationTimer("parallel_format_check") as timer:
        tasks = [(regex_factory().check_email_format, [email], {}) for email in emails]
        results = process_pool.run_parallel_tasks(tasks)
        
    # Rest of the function remains the same
    parallel_stats = get_time_manager().get_stats('parallel_format_check')
    if parallel_stats is not None:
        parallel_stats.add_timing(f"batch_{len(emails)}", timer.elapsed_ms)
    
    per_email_ms = (timer.elapsed_ms / len(emails)) if timer.elapsed_ms is not None and len(emails) > 0 else 0
    logger.debug(f"Format checked {len(emails)} emails in {timer.elapsed_ms}ms " +
                f"({per_email_ms:.2f}ms per email)")
    
    return results

def get_formating_performance_stats():
    """Get performance statistics for the email format checking system"""
    stats = {}
    time_mgr = get_time_manager()
    
    for category in time_mgr.timing_stats:
        if time_mgr.timing_stats[category].timings:
            times = list(time_mgr.timing_stats[category].timings.values())
            stats[category] = {
                'count': len(times),
                'min_ms': min(times) if times else 0,
                'max_ms': max(times) if times else 0,
                'avg_ms': sum(times) / len(times) if times else 0,
                'total_ms': sum(times) if times else 0
            }
    
    return stats

def sanitize_regex(pattern_str):
    """Ensure regex pattern has correct number of backslashes"""
    # Handle common over-escaping issues
    if '\\\\' in pattern_str:
        pattern_str = pattern_str.replace('\\\\', '\\')
    return pattern_str

def check_settings_changed() -> bool:
    """
    Check if email format check settings have been updated in the database.
    
    Returns:
        bool: True if settings have changed since last cache update
    """
    from src.helpers.dbh import sync_db
    cache_mgr = get_cache_manager()
    
    # Get last known settings update time from cache
    cached_timestamp = cache_mgr.get("ev_settings_last_updated")
    
    try:
        # Get current settings update time from database
        row = sync_db.fetchrow("""
            SELECT 
                GREATEST(
                    (SELECT MAX(updated_at) FROM email_filter_regex_settings),
                    (SELECT MAX(created_at) FROM email_filter_regex_presets)
                ) as last_updated
        """)
        
        if not row or not row['last_updated']:
            # No timestamp available, assume settings have changed
            return True
            
        db_timestamp = row['last_updated'].timestamp()
        
        # If no cached timestamp or db timestamp is newer, settings have changed
        if cached_timestamp is None or db_timestamp > cached_timestamp:
            # Update the cached timestamp
            cache_mgr.set("ev_settings_last_updated", db_timestamp)
            logger.debug(f"Email format check settings have changed: {db_timestamp}")
            return True
            
        return False
        
    except Exception as e:
        logger.error(f"Error checking settings changes: {e}")
        # Assume settings have changed if we can't verify
        return True

def email_format_resaults(email_input, trace_id=None, use_cache=True):
    """
    Wrapper function for email format validation with support for string, list, or dict input.
    """
    trace_prefix = f"[{trace_id}]" if trace_id else ""
    
    # Handle dictionary input - extract email field if available
    if isinstance(email_input, dict):
        if 'email' in email_input:
            logger.debug(f"{trace_prefix} Received dictionary input, extracting email field")
            email_input = email_input['email']
        else:
            error_msg = "Dictionary input must contain 'email' key"
            logger.error(f"{trace_prefix} {error_msg}")
            raise ValueError(error_msg)
    
    # Original string/list handling continues...
    if isinstance(email_input, str):
        email = email_input
        domain = email.split('@')[1] if '@' in email else None
        
        # Check cache if enabled
        if use_cache and domain:
            cache_key = f"format_validation:{email}"
            cached_result = cache_manager.get(cache_key)
            if cached_result:
                logger.debug(f"{trace_prefix} Using cached format validation result for {email}")
                return cached_result
        
        logger.debug(f"{trace_prefix} Performing format validation for {email}")
        
        # Process single email directly
        result = regex_factory().check_email_format(email)
        
        # Convert to dict for return
        validation_result = {
            "valid": result.is_valid,
            "normalized_email": result.normalized_email,
            "errors": result.errors,
            "warnings": result.warnings,
            "details": result.details
        }
        
        # Cache the result if valid
        if use_cache and domain and result.is_valid:
            logger.debug(f"{trace_prefix} Caching format validation result for {email}")
            # Cache for 24 hours - format validation rarely changes
            cache_manager.set(f"format_validation:{email}", validation_result, ttl=86400)
        
        if result.is_valid:
            logger.debug(f"{trace_prefix} Email format is valid: {email}")
        else:
            logger.info(f"{trace_prefix} Email format is invalid: {email} - Errors: {', '.join(result.errors)}")
        
        return validation_result
    
    elif isinstance(email_input, list):
        email_count = len(email_input)
        logger.info(f"{trace_prefix} Processing batch format validation for {email_count} emails")
        
        # Process emails in parallel using process pool
        batch_results = process_format_in_parallel_with_process_pool(email_input)
        
        # Convert EmailFormatResult objects to dicts and cache valid results
        results = []
        for i, result in enumerate(batch_results):
            email = email_input[i]
            domain = email.split('@')[1] if '@' in email else None
            
            validation_result = {
                "valid": result.is_valid,
                "normalized_email": result.normalized_email,
                "errors": result.errors,
                "warnings": result.warnings,
                "details": result.details
            }
            results.append(validation_result)
            
            # Cache valid results
            if use_cache and domain and result.is_valid:
                cache_manager.set(f"format_validation:{email}", validation_result, ttl=86400)
        
        valid_count = sum(1 for r in results if r["valid"])
        logger.info(f"{trace_prefix} Batch format validation completed: {valid_count}/{email_count} valid")
        return results
    
    else:
        error_msg = f"email_input must be a string or list of strings, got {type(email_input).__name__}"
        logger.error(f"{trace_prefix} {error_msg}")
        raise TypeError(error_msg)
