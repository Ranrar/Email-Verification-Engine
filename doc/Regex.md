# Regular Expressions in Email Verification Engine

## Table of Contents
1. [What are Regular Expressions?](#what-are-regular-expressions)
2. [Basic Regex Concepts](#basic-regex-concepts)
3. [Email Verification Engine Regex System](#email-verification-engine-regex-system)
4. [Configuration Options](#configuration-options)
5. [Pattern Definitions](#pattern-definitions)
6. [Usage Examples](#usage-examples)
7. [API Reference](#api-reference)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

## What are Regular Expressions?

Regular expressions (regex) are specially formatted text strings used to find patterns in text. They're like a powerful search tool that can match complex patterns instead of just exact text. In email verification, regex helps us validate email format, extract parts, and identify invalid patterns.

### Key Benefits
- **Pattern Matching**: Find specific patterns in email addresses
- **Validation**: Ensure emails follow proper format rules
- **Extraction**: Pull out local parts, domains, and other components
- **Filtering**: Identify and reject invalid email formats

## Basic Regex Concepts

### Literal Characters
Most characters match themselves literally:
```regex
abc     # Matches exactly "abc"
@       # Matches the @ symbol
.com    # Matches ".com" (but . has special meaning - see below)
```

### Metacharacters
Special characters with specific meanings:

| Character | Meaning | Example |
|-----------|---------|---------|
| `.` | Matches any character except newline | `a.c` matches "abc", "axc", "a1c" |
| `^` | Anchors to start of string | `^abc` matches "abc" only at beginning |
| `$` | Anchors to end of string | `abc$` matches "abc" only at end |
| `*` | Matches 0 or more of preceding | `ab*c` matches "ac", "abc", "abbc" |
| `+` | Matches 1 or more of preceding | `ab+c` matches "abc", "abbc" but not "ac" |
| `?` | Matches 0 or 1 of preceding | `ab?c` matches "ac" or "abc" |
| `\` | Escapes special characters | `\.` matches literal dot |

### Character Classes
Square brackets define character sets:
```regex
[abc]       # Matches 'a', 'b', or 'c'
[a-z]       # Matches any lowercase letter
[A-Z]       # Matches any uppercase letter
[0-9]       # Matches any digit
[a-zA-Z0-9] # Matches any alphanumeric character
```

### Predefined Character Classes
```regex
\d    # Matches any digit [0-9]
\w    # Matches any word character [a-zA-Z0-9_]
\s    # Matches any whitespace character
\D    # Matches any non-digit
\W    # Matches any non-word character
\S    # Matches any non-whitespace
```

### Quantifiers
Specify how many times a pattern should match:
```regex
{n}     # Exactly n times
{n,}    # n or more times
{n,m}   # Between n and m times
{1,2}   # 1 or 2 times
{64,}   # 64 or more times (useful for length checks)
```

### Groups and Anchors
```regex
(abc)   # Capturing group - remembers matched text
^       # Start of string
$       # End of string
\b      # Word boundary
```

## Email Verification Engine Regex System

The Email Verification Engine uses a sophisticated regex system with multiple validation layers and configurable patterns. The system is implemented in both Python (`formatcheck.py`) and JavaScript (`regex.js`).

### System Architecture

```
Email Input
    ↓
Basic Format Check (Regex)
    ↓
Normalization (Lowercase, Trim)
    ↓
Length Validation
    ↓
Local Part Validation (Regex)
    ↓
Domain Validation (Regex)
    ↓
IDNA Processing (Unicode domains)
    ↓
Final Result
```

### Core Components

#### 1. EmailFormat Class (Python)
The main validation engine that processes emails through multiple steps:

```python
from src.engine.formatcheck import EmailFormat

# Create instance with default config
checker = EmailFormat()

# Check an email
result = checker.check_email_format("user@example.com")
print(result.is_valid)  # True/False
print(result.errors)    # List of error messages
```

#### 2. Configuration System
Settings are stored in the database and loaded dynamically:

- **Main Settings**: Basic behavior like max lengths
- **Validation Steps**: Which checks to enable/disable
- **Pattern Checks**: Specific regex pattern enforcement
- **Format Options**: Basic format validation options
- **Local Part Options**: Rules for the part before @
- **Domain Options**: Rules for the domain part
- **IDNA Options**: International domain handling

## Configuration Options

### Main Settings

```json
{
  "strict_mode": false,
  "max_local_length": 64,
  "max_domain_length": 255,
  "max_total_length": 320,
  "basic_format_pattern": "basic"
}
```

- **strict_mode**: Enables RFC-strict character validation
- **max_local_length**: Maximum characters before @ (RFC 5322: 64)
- **max_domain_length**: Maximum domain length (RFC 5322: 255)
- **max_total_length**: Maximum total email length (RFC 5322: 320)
- **basic_format_pattern**: "basic" or "rfc5322" pattern selection

### Validation Steps

Controls which validation steps are executed:

```json
{
  "basic_format": true,
  "normalization": true,
  "length_limits": true,
  "local_part": true,
  "domain": true,
  "idna": true
}
```

### Pattern Checks

Specific regex pattern validations:

```json
{
  "empty_parts": true,
  "whitespace": true,
  "consecutive_dots": true
}
```

### Local Part Options

Rules for validating the part before the @ symbol:

```json
{
  "check_consecutive_dots": true,
  "check_chars_strict": true,
  "allowed_chars": "!#$%&'*+-/=?^_`{|}~."
}
```

### Domain Options

Rules for validating the domain part:

```json
{
  "require_dot": true,
  "check_hyphens": true,
  "check_consecutive_dots": true,
  "allowed_chars": ".-"
}
```

### IDNA Options

International domain name handling:

```json
{
  "encode_unicode": true,
  "validate_idna": true
}
```

## Pattern Definitions

The system includes several built-in regex patterns:

### Basic Pattern
```regex
^.+@.+\..+$
```
- `^` - Start of string
- `.+` - One or more of any character (local part)
- `@` - Literal @ symbol
- `.+` - One or more of any character (domain name)
- `\.` - Literal dot (escaped)
- `.+` - One or more of any character (TLD)
- `$` - End of string

**What it matches**: Simple email format with something@domain.tld

### RFC 5322 Pattern
```regex
(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)
```
- `^[a-zA-Z0-9_.+-]+` - Local part: alphanumeric and allowed special chars
- `@` - Literal @ symbol
- `[a-zA-Z0-9-]+` - Domain: alphanumeric and hyphens
- `\.` - Literal dot
- `[a-zA-Z0-9-.]+$` - TLD: alphanumeric, dots, and hyphens

**What it matches**: RFC 5322 compliant email addresses

### Pattern Validation Examples

#### Empty Parts Pattern
```regex
^@|@$|@\.|\.$ 
```
- `^@` - Starts with @
- `@$` - Ends with @
- `@\.` - @ followed by dot
- `\.$` - Ends with dot

**Catches**: @domain.com, user@, user@.com, user@domain.

#### Whitespace Pattern
```regex
\s+
```
- `\s+` - One or more whitespace characters

**Catches**: user @domain.com, user@ domain.com

#### Consecutive Dots Pattern
```regex
\.{2,}
```
- `\.{2,}` - Two or more consecutive dots

**Catches**: user..name@domain.com, user@domain..com

## Usage Examples

### Basic Usage (Python)

```python
from src.engine.formatcheck import regex_factory, email_format_resaults

# Method 1: Using factory function
checker = regex_factory()
result = checker.check_email_format("user@example.com")

# Method 2: Using wrapper function
result = email_format_resaults("user@example.com")

# Method 3: Batch processing
emails = ["user1@example.com", "user2@domain.com", "invalid-email"]
results = email_format_resaults(emails)
```

### Configuration Examples

#### Creating Custom Configuration
```python
custom_config = {
    "strict_mode": True,
    "max_local_length": 32,  # Stricter than RFC
    "basic_format_pattern": "rfc5322",
    "pattern_checks": {
        "empty_parts": True,
        "whitespace": True,
        "consecutive_dots": True
    }
}

checker = EmailFormat(custom_config)
```

#### Loading from Database
```python
# Uses active configuration (nr=1) from database
checker = regex_factory(use_cached_config=False)  # Force refresh
```

### Web Interface Usage (JavaScript)

#### Loading Settings
```javascript
// Load email filter regex settings
await loadEmailFilterRegexSettings();

// Access current settings
console.log(emailFilterState.settings);
console.log(emailFilterState.presets);
```

#### Applying Presets
```javascript
// Apply a preset configuration
const presetSelect = document.getElementById('email-filter-preset-select');
presetSelect.value = '1';  // Select preset ID 1
await applyEmailFilterRegexPreset();
```

#### Creating New Configuration
```javascript
// Create new configuration
const configData = {
    name: "Custom Gmail Validator",
    description: "Strict validation for Gmail addresses",
    main_settings: {
        strict_mode: true,
        max_local_length: 64,
        basic_format_pattern: "rfc5322"
    },
    // ... other settings
};

const result = await eel.create_new_email_filter_regex_configuration(configData)();
```

## API Reference

### Python Functions

#### `regex_factory(use_cached_config=True)`
Creates an EmailFormat instance with configuration.

**Parameters:**
- `use_cached_config` (bool): Whether to use cached configuration

**Returns:**
- `EmailFormat`: Configured email format checker instance

#### `email_format_resaults(email_input, trace_id=None, use_cache=True)`
Validates email format with support for various input types.

**Parameters:**
- `email_input` (str|list|dict): Email(s) to validate
- `trace_id` (str, optional): Trace ID for logging
- `use_cache` (bool): Whether to use caching

**Returns:**
- `dict|list`: Validation results

#### `EmailFormat.check_email_format(email)`
Core validation method.

**Parameters:**
- `email` (str): Email address to validate

**Returns:**
- `EmailFormatResult`: Detailed validation result

### EmailFormatResult Object

```python
@dataclass
class EmailFormatResult:
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
```

### JavaScript Functions

#### `loadEmailFilterRegexSettings()`
Loads settings and presets from the database.

**Returns:**
- `Promise<boolean>`: Success status

#### `applyEmailFilterRegexPreset()`
Applies selected preset or custom configuration.

#### `saveNewEmailFilterConfiguration()`
Saves a new email filter configuration.

#### `renderConfigurationStructure(config, readOnly)`
Renders the configuration form UI.

**Parameters:**
- `config` (object): Configuration data
- `readOnly` (boolean): Whether form is read-only

## Best Practices

### 1. Use Appropriate Validation Levels
- **Permissive**: For user registration (catch obvious errors)
- **Standard**: For general email collection
- **Strict**: For high-quality email lists

### 2. Handle Unicode Domains
```python
# Enable IDNA encoding for international domains
config = {
    "idna_options": {
        "encode_unicode": True,
        "validate_idna": True
    }
}
```

### 3. Cache Configuration
```python
# Use cached configuration for performance
checker = regex_factory(use_cached_config=True)
```

### 4. Batch Processing
```python
# Process multiple emails efficiently
emails = ["user1@example.com", "user2@domain.com"]
results = email_format_resaults(emails)
```

### 5. Error Handling
```python
try:
    result = checker.check_email_format(email)
    if not result.is_valid:
        print(f"Validation errors: {result.errors}")
except Exception as e:
    print(f"Validation failed: {e}")
```

## Troubleshooting

### Common Issues

#### 1. Configuration Not Loading
```python
# Force refresh configuration
checker = regex_factory(use_cached_config=False)
```

#### 2. Unicode Domain Issues
```python
# Check IDNA settings
result = checker.check_email_format("user@münchen.de")
print(result.ascii_domain)  # Should show xn-- encoded domain
```

#### 3. Performance Issues
```python
# Use batch processing for multiple emails
# Enable caching
# Check timing statistics
stats = get_formating_performance_stats()
```

#### 4. Pattern Matching Problems
```python
# Debug pattern matching
result = checker.check_email_format(email)
print(result.format_check_steps)  # Shows which steps passed/failed
print(result.details)  # Additional debugging info
```

### Debugging Tips

1. **Check Step Results**: Use `format_check_steps` to see which validation steps failed
2. **Review Error Messages**: Check `errors` and `warnings` arrays for specific issues  
3. **Validate Configuration**: Ensure your regex patterns are properly escaped
4. **Test Incrementally**: Start with basic patterns and add complexity gradually
5. **Use Trace IDs**: Include trace IDs for better log correlation

### Performance Optimization

1. **Use Caching**: Enable configuration and result caching
2. **Batch Processing**: Process multiple emails together
3. **Selective Validation**: Disable unnecessary validation steps
4. **Monitor Stats**: Use `get_formating_performance_stats()` to track performance

## Example Configurations

### Gmail-Only Validator
```json
{
  "name": "Gmail Validator",
  "description": "Validates only Gmail addresses",
  "main_settings": {
    "strict_mode": true,
    "basic_format_pattern": "rfc5322"
  },
  "custom_patterns": {
    "gmail_only": "^[a-zA-Z0-9._%+-]+@gmail\\.com$"
  }
}
```

### Permissive International
```json
{
  "name": "International Permissive",
  "description": "Allows international domains with minimal validation",
  "main_settings": {
    "strict_mode": false,
    "basic_format_pattern": "basic"
  },
  "idna_options": {
    "encode_unicode": true,
    "validate_idna": true
  }
}
```

### Ultra-Strict Corporate
```json
{
  "name": "Corporate Strict",
  "description": "Maximum validation for corporate email lists",
  "main_settings": {
    "strict_mode": true,
    "max_local_length": 32,
    "basic_format_pattern": "rfc5322"
  },
  "pattern_checks": {
    "empty_parts": true,
    "whitespace": true,
    "consecutive_dots": true
  },
  "local_part_options": {
    "check_chars_strict": true,
    "allowed_chars": "._-"
  }
}
```

---

This documentation provides a comprehensive guide to understanding and using regular expressions in the Email Verification Engine. For additional help, refer to the source code in `formatcheck.py` and `regex.js`.