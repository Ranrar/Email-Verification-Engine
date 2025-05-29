-- Email Verification Engine
-- SQL schema for PostgreSQL

-- Set timezone to UTC globally for consistent timestamp handling
SET timezone = 'UTC';

-- =============================================
-- Core system tables
-- =============================================

-- users
CREATE TABLE IF NOT EXISTS users (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,                     
    created_at TIMESTAMPTZ NOT NULL,          
    is_active BOOLEAN DEFAULT FALSE,
    suspended_date TIMESTAMPTZ,               
    signup_location TEXT,
    signup_IP TEXT                  
);

-- audit_log
CREATE TABLE IF NOT EXISTS audit_log (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    action TEXT,
    status TEXT,
    message TEXT,
    severity TEXT DEFAULT 'info',
    ip_address TEXT,
    source TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Main table: email_validation_functions
CREATE TABLE IF NOT EXISTS email_validation_functions (
    id SERIAL PRIMARY KEY,
    function_name VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100,
    enabled BOOLEAN DEFAULT TRUE,
    module_path VARCHAR(255) NOT NULL,
    function_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Populate email_validation_functions table with core validation steps
INSERT INTO email_validation_functions (function_name, display_name, description, priority, enabled, module_path, function_path) VALUES
('validate_domain', 'Domain Existence Check', 'Verifies domain existence via DNS before other validations', 5, True, 'src.engine.functions.validate_domain', 'validate_domain'),
('email_format_resaults', 'Email Format Check', 'Validates email format syntax and structure', 10, True, 'src.engine.formatcheck', 'email_format_resaults'),
('blacklist_check', 'Black/White List Check', 'Checks if domain is whitelisted, blacklisted, or temporarily blocked', 20, true, 'src.engine.functions.bw', 'check_black_white'),
('mx_records', 'MX Records', 'Checks for valid mail exchanger records', 30, True, 'src.engine.functions.mx', 'fetch_mx_records'),
('whois_info', 'WHOIS Information', 'Retrieves domain registration information', 35, true, 'src.engine.functions.mx', 'fetch_whois_info'),
('smtp_validation', 'SMTP Validation', 'Verifies mailbox existence via SMTP connection', 40, true, 'src.engine.functions.smtp', 'validate_smtp'),
-- not implementet yet
('spf_check', 'SPF Validation', 'Checks Sender Policy Framework records', 50, true, 'src.engine.functions.1', '1'),
('dkim_check', 'DKIM Validation', 'Checks DomainKeys Identified Mail status', 60, true, 'src.engine.functions.2', '2'),
('dmarc_check', 'DMARC Policy', 'Checks Domain-based Message Authentication policy', 70, true, 'src.engine.functions.3', '3'),
('catch_all_check', 'Catch-All Detection', 'Checks if domain accepts all emails', 80, true, 'src.engine.functions.4', '4'),
('imap_check', 'IMAP Verification', 'Checks if domain has IMAP service', 90, true, 'src.engine.functions.5', '5'),
('pop3_check', 'POP3 Verification', 'Checks if domain has POP3 service', 100, true, 'src.engine.functions.6', '6'),
('disposable_check', 'Disposable Email', 'Checks if email is from disposable email service', 110, true, 'src.engine.engine.7', '7')
ON CONFLICT (function_name) DO NOTHING;

-- Dependency table: email_validation_function_dependencies
CREATE TABLE IF NOT EXISTS email_validation_function_dependencies (
    id SERIAL PRIMARY KEY,
    function_name VARCHAR(255) NOT NULL REFERENCES email_validation_functions(function_name) ON DELETE CASCADE,
    depends_on VARCHAR(255) NOT NULL REFERENCES email_validation_functions(function_name) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (function_name, depends_on)
);

-- Primary validation sequence
INSERT INTO email_validation_function_dependencies (function_name, depends_on) VALUES
('mx_records', 'email_format_resaults'),
('whois_info', 'email_format_resaults'),
('smtp_validation', 'mx_records'),
('spf_check', 'mx_records'),
('dkim_check', 'mx_records'),
('dmarc_check', 'mx_records'),
('catch_all_check', 'smtp_validation'),
('imap_check', 'mx_records'),
('pop3_check', 'mx_records'),
('disposable_check', 'email_format_resaults'),
('validate_domain', 'email_format_resaults'),
('mx_records', 'validate_domain'),
('blacklist_check', 'validate_domain'),
('whois_info', 'validate_domain'),
('mx_records', 'blacklist_check')
ON CONFLICT (function_name, depends_on) DO NOTHING;

-- batch_info
CREATE TABLE IF NOT EXISTS batch_info (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT,
    source TEXT,
    created_at TIMESTAMPTZ NOT NULL,          
    completed_at TIMESTAMPTZ,                 
    total_emails INTEGER DEFAULT 0,
    processed_emails INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'queued',
    error_message TEXT,
    settings_snapshot JSONB
);

-- Main validation results table with trace_id as primary identifier
CREATE TABLE IF NOT EXISTS email_validation_records (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trace_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,           
    email TEXT NOT NULL,
    domain TEXT NOT NULL,
    smtp_result TEXT,
    smtp_banner TEXT,
    smtp_vrfy TEXT,
    smtp_supports_tls BOOLEAN,
    smtp_supports_auth BOOLEAN,
    smtp_flow_success BOOLEAN,
    smtp_error_code INTEGER,
    smtp_server_message TEXT,
    port TEXT,
    mx_records TEXT,
    mx_ip TEXT,
    mx_preferences TEXT,
    mx_analysis JSONB,
    email_provider_id INTEGER,
    email_provider_info JSONB,
    reverse_dns TEXT,
    whois_info TEXT,
    catch_all TEXT,
    imap_status TEXT,
    imap_info TEXT,
    imap_security TEXT,
    pop3_status TEXT,
    pop3_info TEXT,
    pop3_security TEXT,
    spf_status TEXT,
    dkim_status TEXT,
    dmarc_status TEXT,
    server_policies TEXT,
    disposable TEXT,
    blacklist_info TEXT,
    error_message TEXT,
    is_valid BOOLEAN DEFAULT FALSE,
    confidence_score INTEGER DEFAULT 0,
    execution_time REAL DEFAULT 0,
    timing_details TEXT,
    check_count INTEGER DEFAULT 1,
    batch_id INTEGER NULL,
    raw_result JSONB,
    validation_complete BOOLEAN DEFAULT FALSE,
    CONSTRAINT unique_trace_id UNIQUE (trace_id),
    CONSTRAINT fk_batch FOREIGN KEY (batch_id) REFERENCES batch_info(id) ON DELETE SET NULL
);

-- app_settings
CREATE TABLE IF NOT EXISTS app_settings (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category TEXT NOT NULL,
    sub_category  TEXT NOT NULL,         
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    UNIQUE(description)
);

INSERT INTO app_settings (category, sub_category, name, value, description) VALUES
('http', 'user_agent', 'name', 'EmailVerificationEngine', 'Name for User-Agent'),
('http', 'user_agent', 'version', '0.2', 'Version for User-Agent'),
('http', 'user_agent', 'url', 'https://github.com/Ranrar/Email-Verification-Engine', 'URL for User-Agent contact'),
-- ('http', 'user_agent', 'email', 'verification@example.com', 'email for User-Agent contact'),
('email', 'defaults', 'sender email', 'EmailVerificationEngine@example.com', 'Default sender email address for SMTP verification'),
('Settings', 'Cache', 'cache purge', '30', 'Seconds between cache check TTL to purge for L1, L2 and L3 cache'),
('Settings', 'Debug', 'Enable', '1', 'Enable Debug menu 1=True 0=False'),
('Settings', 'Start', 'Enable', '0', 'Enable Auto-benchmark during start 1=True 0=False'),
('Database', 'Backup', 'Enable', '1', 'Enable database backup 1=True 0=False'),
('Database', 'Backup', 'Count', '5', 'Number of backups to keep'),
('Database', 'Backup', 'TimeUTC', '02:00', 'Time (UTC) to run backup (HH:MM)')
ON CONFLICT (description) DO NOTHING;

-- Create a function that prevents modifications to user agent settings
CREATE OR REPLACE FUNCTION protect_user_agent_settings()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if we're trying to modify user agent settings
    IF (OLD.category = 'http' AND OLD.sub_category = 'user_agent' AND 
        OLD.name IN ('name', 'version', 'url')) THEN
        RAISE EXCEPTION 'User Agent settings (name, version, url) are read-only and cannot be modified';
    END IF;
    
    -- For all other rows, allow the operation
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Create triggers to protect against updates and deletes
CREATE TRIGGER prevent_user_agent_updates
BEFORE UPDATE ON app_settings
FOR EACH ROW
EXECUTE FUNCTION protect_user_agent_settings();

CREATE TRIGGER prevent_user_agent_deletes
BEFORE DELETE ON app_settings
FOR EACH ROW
EXECUTE FUNCTION protect_user_agent_settings();

-- validation scoring
CREATE TABLE IF NOT EXISTS validation_scoring (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    check_name TEXT NOT NULL UNIQUE,
    score_value INTEGER NOT NULL,
    is_penalty BOOLEAN NOT NULL,
    description TEXT
);

INSERT INTO validation_scoring (check_name, score_value, is_penalty, description) VALUES
('valid_format', 20, FALSE, 'Email has valid format'),
('not_disposable', 10, FALSE, 'Email is not from a disposable provider'),
('disposable', 10, TRUE, 'Email is from a disposable provider'),
('blacklisted', 15, TRUE, 'Domain is blacklisted'),
('mx_records', 20, FALSE, 'Domain has valid MX records'),
('spf_found', 5, FALSE, 'Domain has SPF record'),
('dkim_found', 5, FALSE, 'Domain has DKIM record'),
('smtp_connection', 30, FALSE, 'SMTP connection successful'),
('catch_all', 15, TRUE, 'Domain accepts catch-all emails'),
('no_catch_all', 15, FALSE, 'Domain does not accept catch-all emails'),
('vrfy_confirmed', 10, FALSE, 'VRFY command confirms email'),
('imap_available', 5, FALSE, 'IMAP service available'),
('pop3_available', 5, FALSE, 'POP3 service available')
ON CONFLICT (check_name) DO NOTHING;

-- confidence levels
CREATE TABLE IF NOT EXISTS confidence_levels (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    level_name TEXT NOT NULL UNIQUE,
    min_threshold INTEGER NOT NULL,
    max_threshold INTEGER NOT NULL,
    description TEXT
);

INSERT INTO confidence_levels (level_name, min_threshold, max_threshold, description) VALUES
('Very High', 90, 100, 'Email almost certainly exists'),
('High', 70, 89, 'Email very likely exists'),
('Medium', 50, 69, 'Email probably exists'),
('Low', 30, 49, 'Email may exist but verification is uncertain'),
('Very Low', 0, 29, 'Email likely doesnt exist')
ON CONFLICT (level_name) DO NOTHING;

-- ports
CREATE TABLE IF NOT EXISTS ports (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category TEXT NOT NULL,
    port INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    description TEXT,
    UNIQUE(description)
);

INSERT INTO ports (category, port, priority, enabled, description) VALUES
('smtp', 25, 3, TRUE, 'No encryption, None/TLS, server-to-server (relay)'),
('smtp', 587, 1, TRUE, 'Encryption with STARTTLS, client-to-server (recommended)'),
('smtp', 465, 2, TRUE, 'Encryption with SSL/TLS, client-to-server (legacy support)'),

-- Domain/MX ports
('dns', 53, 1, TRUE, 'MX record lookup via DNS for mail server hostnames (TCP/UDP)'),
('dns', 53, 2, TRUE, 'Reverse DNS (PTR) lookup via DNS for IP-to-domain mapping (TCP/UDP)'),
('dns', 53, 3, TRUE, 'SPF record lookup via DNS TXT record (TCP/UDP)'),
('dns', 53, 4, TRUE, 'DKIM record lookup via DNS TXT record for public key validation (TCP/UDP)'),
('dns', 53, 5, TRUE, 'DMARC record lookup via DNS TXT record for policy retrieval (TCP/UDP)'),
('dns', 53, 6, TRUE, 'DNSBL lookup for checking spam source listings (TCP/UDP)'),
('whois', 43, 7, TRUE, 'WHOIS lookup via TCP for domain registration details'),
('rdap', 443, 8, TRUE, 'RDAP lookup via HTTPS (TLS over TCP) for structured domain registration info'),
('rdap', 80, 9, TRUE, 'RDAP fallback lookup via HTTP for domain registration info'),

-- Authentication and security ports
('auth', 53, 1, TRUE, 'SPF lookup: DNS TXT record for SPF validation'),
('auth', 53, 2, TRUE, 'DKIM lookup: DNS TXT record for DKIM public key'),
('auth', 53, 3, TRUE, 'DMARC lookup: DNS TXT record for DMARC policy'),
('auth', 25, 4, TRUE, 'SMTP policy check: banner, STARTTLS/AUTH on port 25'),
('auth', 587, 5, TRUE, 'SMTP submission: STARTTLS/AUTH on port 587'),
('auth', 465, 6, TRUE, 'SMTPS: implicit SSL/TLS on port 465'),
('auth', 53, 7, TRUE, 'DNSSEC check: validate DNSSEC signatures'),
('auth', 53, 8, TRUE, 'TLS-RPT lookup: _smtp._tls TXT record'),
('auth', 443, 9, TRUE, 'MTA-STS policy fetch over HTTPS'),
('auth', 25, 10, TRUE, 'TLS version & cipher suite probe on port 25'),

-- Additional ports
('mail', 25, 1, TRUE, 'SMTP - Default port used for RCPT TO and catch-all testing'),
('mail', 587, 2, TRUE, 'SMTP - Submission port with STARTTLS support'),
('mail', 465, 3, TRUE, 'SMTP - Implicit TLS for secure email submission (legacy support)'),
('mail', 143, 4, TRUE, 'IMAP - Default port, typically used with STARTTLS'),
('mail', 993, 5, TRUE, 'IMAP - Implicit TLS for secure IMAP connections'),
('mail', 110, 6, TRUE, 'POP3 - Default port, typically used with STARTTLS'),
('mail', 995, 7, TRUE, 'POP3 - Implicit TLS for secure POP3 connections')
ON CONFLICT (description) DO NOTHING;

-- rate_limits
CREATE TABLE IF NOT EXISTS rate_limit (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    is_time BOOLEAN NOT NULL,
    enabled BOOLEAN NOT NULL,
    description TEXT,
    UNIQUE(name)
);

INSERT INTO rate_limit (category, name, value, is_time, enabled, description) VALUES
('smtp', 'max_retries', 3, FALSE, TRUE, 'Maximum number of SMTP connection attempts'),
('smtp', 'max_connections_per_minute', 60, FALSE, TRUE, 'Maximum number of connections per minute globally'),
('smtp', 'max_connections_per_domain', 5, FALSE, TRUE, 'Maximum number of connections per domain per minute'),
('smtp', 'max_vrfy_per_minute', 2, FALSE, TRUE, 'Maximum number of VRFY requests per domain per minute'),
('smtp', 'max_mx_requests_per_minute', 100, FALSE, TRUE, 'Maximum number of MX record requests per minute'),
('smtp', 'max_spf_dkim_dmarc_requests_per_minute', 100, FALSE, TRUE, 'Maximum number of SPF/DKIM/DMARC requests per minute'),
('smtp', 'max_banner_requests_per_minute', 100, FALSE, TRUE, 'Maximum number of banner requests per minute'),
('smtp', 'max_reverse_dns_requests_per_minute', 100, FALSE, TRUE, 'Maximum number of reverse DNS (PTR) requests per minute'),
('smtp', 'max_whois_requests_per_minute', 15, FALSE, TRUE, 'Maximum number of WHOIS requests per minute'),
('smtp', 'timeout_block_duration', 600, TRUE, TRUE, 'Duration in seconds to block domains after timeout'),
('smtp', 'rate_limit_block_duration', 300, TRUE, TRUE, 'Duration in seconds to block domains after rate limit violation'),

-- SMTP rate limits - Time based (seconds)
('smtp', 'timeout_connect', 10, TRUE, TRUE, 'Timeout in seconds when establishing a connection'),
('smtp', 'timeout_read', 30, TRUE, TRUE, 'Timeout in seconds when waiting for server response'),
('smtp', 'timeout_overall', 60, TRUE, TRUE, 'Maximum allowed time for the entire operation (connection + communication)'),

-- Domain/MX rate limits - All time based
('dom_mx', 'mx_records_cache_ttl', 86400, TRUE, TRUE, 'MX record cache duration in seconds (1 day)'),
('dom_mx', 'mx_ip_cache_ttl', 86400, TRUE, TRUE, 'MX IP address cache duration in seconds (1 day)'),
('dom_mx', 'mx_preferences_cache_ttl', 86400, TRUE, TRUE, 'MX preferences cache duration in seconds (1 day)'),
('dom_mx', 'reverse_dns_cache_ttl', 86400, TRUE, TRUE, 'Reverse DNS (PTR) cache duration in seconds (1 day)'),
('dom_mx', 'whois_cache_ttl', 604800, TRUE, TRUE, 'WHOIS info cache duration in seconds (7 days)'),

-- Authentication/Security rate limits - Mixed
('auth_security', 'spf_max_lookups', 10, FALSE, TRUE, 'Max 10 DNS lookups per domain (SPF spec)'),
('auth_security', 'smtp_port25_conn_interval', 10, TRUE, TRUE, 'Minimum seconds between connections on port 25 per domain'),
('auth_security', 'smtp_port587_conn_interval', 30, TRUE, TRUE, 'Minimum seconds between connections on ports 587/465 per domain'),
('auth_security', 'smtp_banner_grab_interval', 3600, TRUE, TRUE, 'Minimum seconds between banner grabs per domain'),
('auth_security', 'mta_sts_fetch_interval', 86400, TRUE, TRUE, 'Fetch MTA-STS policy once per 24 h'),
('auth_security', 'tls_cipher_interval', 600, TRUE, TRUE, 'ciphers/TLS every 10 min'),
('auth_security', 'query_timeout', 20, TRUE, TRUE, 'Timeout in seconds for auth/security related queries'),

-- Additional rate limits - Mixed
('additional', 'catch_all_rcpt_limit_per_min', 6, FALSE, TRUE, 'Max RCPT TO commands per minute per IP'),
('additional', 'catch_all_smtp_concurrent_limit', 10, FALSE, TRUE, 'Max concurrent SMTP connections per IP'),
('additional', 'imap_connection_limit_per_min', 5, FALSE, TRUE, 'Max IMAP connections per minute per IP'),
('additional', 'imap_concurrent_sessions', 16, FALSE, TRUE, 'Max concurrent IMAP sessions per user/IP'),
('additional', 'pop3_connection_limit_per_min', 5, FALSE, TRUE, 'Max POP3 connections per minute per IP'),
('additional', 'pop3_concurrent_sessions', 16, FALSE, TRUE, 'Max concurrent POP3 sessions per user/IP'),
('additional', 'connection_timeout', 30, TRUE, TRUE, 'Connection timeout in seconds for additional protocols'),

-- cache rate limits - All time based
('cache', 'cache_duration_mx_spf_dkim_dmarc', 86400, TRUE, TRUE, 'Cache duration for MX/SPF/DKIM/DMARC results (86400 seconds = 24 hours)'),
('cache', 'cache_duration_reverse_dns', 86400, TRUE, TRUE, 'Cache duration for reverse DNS results (86400 seconds = 24 hours)'),
('cache', 'cache_duration_banner', 86400, TRUE, TRUE, 'Cache duration for SMTP banner results (86400 seconds = 24 hours)'),
('cache', 'cache_duration_smtp_result', 21600, TRUE, TRUE, 'Cache duration for SMTP result per domain (21600 seconds = 6 hours)'),
('cache', 'cache_duration_smtp_vrfy', 3600, TRUE, TRUE, 'Cache duration for SMTP VRFY results (3600 seconds = 1 hour)'),
('cache', 'cache_duration_smtp_port', 172800, TRUE, TRUE, 'Cache duration for SMTP port results per domain (172800 seconds = 48 hours)'),
('cache', 'cache_duration_whois', 259200, TRUE, TRUE, 'Cache duration for WHOIS results (259200 seconds = 72 hours)'),
('cache', 'spf_cache_ttl', 900, TRUE, TRUE, 'Cache SPF results for 5-15 minutes'),
('cache', 'dkim_cache_ttl', 3600, TRUE, TRUE, 'Cache DKIM results for 1-6 hours based on TTL'),
('cache', 'dmarc_cache_ttl', 3600, TRUE, TRUE, 'Cache DMARC results for 1-6 hours based on TTL'),
('cache', 'dnssec_cache_ttl', 86400, TRUE, TRUE, 'Cache DNSSEC validity for 24 h'),
('cache', 'tls_rpt_cache_ttl', 86400, TRUE, TRUE, 'Cache TLS-RPT TXT for 24 h'),
('cache', 'smtp_domain_stats_ttl', 3600, TRUE, TRUE, 'Cache TTL for SMTP domain statistics (1 hour)'),
('cache', 'smtp_attempt_history_ttl', 86400, TRUE, TRUE, 'Cache TTL for SMTP attempt history (24 hours)'),
('cache', 'smtp_blocked_cache_ttl', 60, TRUE, TRUE, 'Cache TTL for SMTP temporary blocklist checks (60 seconds)'),

-- DNS request rate limits
('dns', 'mx_lookup', 120, FALSE, TRUE, 'Maximum MX record lookups per minute'),
('dns', 'a_lookup', 150, FALSE, TRUE, 'Maximum A record lookups per minute'),
('dns', 'aaaa_lookup', 100, FALSE, TRUE, 'Maximum AAAA record lookups per minute'),
('dns', 'txt_lookup', 100, FALSE, TRUE, 'Maximum TXT record lookups per minute'),
('dns', 'ptr_lookup', 60, FALSE, TRUE, 'Maximum PTR record lookups per minute'),
('dns', 'cname_lookup', 100, FALSE, TRUE, 'Maximum CNAME record lookups per minute'),
('dns', 'ns_lookup', 50, FALSE, TRUE, 'Maximum NS record lookups per minute'),
('dns', 'soa_lookup', 30, FALSE, TRUE, 'Maximum SOA record lookups per minute'),
('dns', 'ip_lookup', 60, FALSE, TRUE, 'Maximum IP lookups per minute for domain hosts'),

-- DNS timeout settings
('dns', 'lookup_timeout', 10, TRUE, TRUE, 'DNS query timeout in seconds'),
('dns', 'retry_interval', 2, TRUE, TRUE, 'Seconds between retry attempts'),
('dns', 'min_mx_records', 1, FALSE, TRUE, 'Minimum required MX records for domain to be valid'),
('dns', 'max_lookups_per_domain', 20, FALSE, TRUE, 'Maximum DNS lookups per domain per minute')
ON CONFLICT (name) DO NOTHING;

-- executor_pool_settings
CREATE TABLE IF NOT EXISTS executor_pool_settings (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL,
    is_time BOOLEAN NOT NULL,
    description TEXT,
    UNIQUE(name)
);

INSERT INTO executor_pool_settings (name, value, is_time, description) VALUES

-- ThreadPoolExecutor
('max_worker_threads', 10, FALSE, 'Maximum number of worker threads for parallel tasks'),
('min_worker_threads', 2, FALSE, 'Minimum number of worker threads for parallel tasks'),

-- ProcessPoolExecutor
('max_processes', 4, FALSE, 'Maximum number of worker processes for parallel processing'),
('min_processes', 1, FALSE, 'Minimum number of worker processes for parallel processing'),

-- settings
('process_timeout', 300, TRUE, 'Default timeout in seconds for process pool tasks'),
('max_tasks_per_process', 100, FALSE, 'Maximum number of tasks before process worker restarts')
ON CONFLICT (name) DO NOTHING;

-- executor_pool_presets
CREATE TABLE IF NOT EXISTS executor_pool_presets (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    settings_json JSONB NOT NULL,
    description TEXT
);

INSERT INTO executor_pool_presets (name, settings_json, description) VALUES
(
    'safe',
    '{
        "max_worker_threads": 4,
        "min_worker_threads": 1,
        "max_processes": 1,
        "min_processes": 1,
        "process_timeout": 600,
        "max_tasks_per_process": 25
    }',
    'Very conservative settings for minimal resource usage and maximum safety.'
),
(
    'balanced',
    '{
        "max_worker_threads": 10,
        "min_worker_threads": 2,
        "max_processes": 4,
        "min_processes": 1,
        "process_timeout": 300,
        "max_tasks_per_process": 100
    }',
    'Balanced settings for typical workloads.'
),
(
    'performance',
    '{
        "max_worker_threads": 32,
        "min_worker_threads": 4,
        "max_processes": 8,
        "min_processes": 2,
        "process_timeout": 120,
        "max_tasks_per_process": 200
    }',
    'Aggressive settings for high-performance environments.'
)
ON CONFLICT (name) DO NOTHING;

-- Log all benchmarks
CREATE TABLE IF NOT EXISTS executor_pool_benchmark_log (
    id SERIAL PRIMARY KEY,
    run_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    run_type TEXT NOT NULL,
    benchmark_results JSONB NOT NULL,
    notes TEXT
);

-- DNS settings
CREATE TABLE IF NOT EXISTS dns_settings (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    is_time BOOLEAN NOT NULL,
    description TEXT
);

INSERT INTO dns_settings (name, value, is_time, description) VALUES

-- Time-based settings (is_time = 1)
('timeout', '10', TRUE, 'Timeout for DNS queries in seconds'),
('stats_retention_days', '30', TRUE, 'Number of days to retain DNS server statistics'),

-- Non-time based settings
('nameservers', '8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,9.9.9.10,149.112.112.112,208.67.222.222,208.67.220.220', FALSE, 'Comma-separated list of DNS nameservers'),
('collect_stats', '1', FALSE, 'Whether to collect DNS server performance statistics (1 = yes, 0 = no)'),
('selection_strategy', 'best_performer', FALSE, 'DNS server selection strategy (random, round_robin, best_performer)'),
('max_attempts', '3', FALSE, 'Maximum number of attempts when resolving DNS records'),
('max_queries_per_minute', '60', FALSE, 'Maximum DNS queries allowed per minute total'),
('max_queries_per_domain', '5', FALSE, 'Maximum DNS queries allowed per minute for a specific domain'),
('use_edns', '1', FALSE, 'Use EDNS extensions for DNS queries (1 = yes, 0 = no)'),
('use_tcp', '0', FALSE, 'Force TCP for DNS queries instead of UDP (1 = yes, 0 = no)'),
('use_dnssec', '1', FALSE, 'Enable DNSSEC validation for DNS queries (1 = yes, 0 = no)'),
('prefer_ipv6', '1', FALSE, 'Prefer IPv6 addresses when available (1 = yes, 0 = no)')
ON CONFLICT (name) DO NOTHING;

-- DNS server statistics table for monitoring performance and reliability
CREATE TABLE IF NOT EXISTS dns_server_stats (
    id SERIAL PRIMARY KEY,
    nameserver TEXT NOT NULL,
    query_type TEXT NOT NULL,
    status TEXT NOT NULL,  -- 'success' or 'failure'
    response_time_ms FLOAT NULL,  -- only for successful queries
    error_message TEXT NULL,      -- only for failed queries
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- email_filter_regex_presets
CREATE TABLE IF NOT EXISTS email_filter_regex_presets (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    main_settings_config JSONB NOT NULL,
    validation_steps_config JSONB NOT NULL,
    pattern_checks_config JSONB NOT NULL,
    format_options_config JSONB NOT NULL,
    local_part_options_config JSONB NOT NULL,
    domain_options_config JSONB NOT NULL,
    idna_options_config JSONB NOT NULL,
    regex_pattern_config JSONB NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL           
);

INSERT INTO email_filter_regex_presets (name, main_settings_config, validation_steps_config, pattern_checks_config, format_options_config, local_part_options_config, domain_options_config, idna_options_config, regex_pattern_config, description, created_at) VALUES
-- Default Configuration
(
'Standard Configuration', 
'{"strict_mode": false, "max_local_length": 64, "max_domain_length": 255, "max_total_length": 320, "basic_format_pattern": "basic"}',
'{"basic_format": true, "normalization": true, "length_limits": true, "local_part": true, "domain": true, "idna": true}',
'{"empty_parts": true, "whitespace": true, "consecutive_dots": true}',
'{"check_empty_parts": true, "check_whitespace": true, "check_pattern": true}',
'{"check_consecutive_dots": true, "check_chars_strict": true, "allowed_chars": "!--$%&''*+-/=?^_`{|}~."}',
'{"require_dot": true, "check_hyphens": true, "check_consecutive_dots": true, "allowed_chars": ".-"}',
'{"encode_unicode": true, "validate_idna": true}',
'{"basic": "^.+@.+\\..+$", "rfc5322": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)", "local_too_long": "^.{64,}@", "empty_parts": "^@|@$|@\\.|\\.$", "whitespace": "\\s+", "consecutive_dots": "\\.{2,}"}',
'Standard email validation configuration based on RFC standards',
'2025-04-30T00:00:00Z'
),

-- Permissive Configuration
(
'Permissive Validation', 
'{"strict_mode": false, "max_local_length": 100, "max_domain_length": 255, "max_total_length": 355, "basic_format_pattern": "basic"}',
'{"basic_format": true, "normalization": true, "length_limits": false, "local_part": false, "domain": false, "idna": false}',
'{"empty_parts": true, "whitespace": true, "consecutive_dots": false}',
'{"check_empty_parts": true, "check_whitespace": true, "check_pattern": true}',
'{"check_consecutive_dots": false, "check_chars_strict": false, "allowed_chars": "!--$%&''*+-/=?^_`{|}~.[]"}',
'{"require_dot": false, "check_hyphens": false, "check_chars": false, "check_consecutive_dots": false, "allowed_chars": ".-_"}',
'{"encode_unicode": true, "validate_idna": false}',
'{"basic": "^.+@.+", "rfc5322": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)", "local_too_long": "^.{100,}@", "empty_parts": "^@|@$", "whitespace": "\\s+", "consecutive_dots": "\\.{2,}"}',
'Very permissive validation that accepts most formats including non-standard ones',
'2025-04-30T00:00:00Z'
),

-- Unicode-focused Configuration
(
'Unicode Email Support', 
'{"strict_mode": false, "max_local_length": 64, "max_domain_length": 255, "max_total_length": 320, "basic_format_pattern": "basic"}',
'{"basic_format": true, "normalization": true, "length_limits": true, "local_part": true, "domain": true, "idna": true}',
'{"empty_parts": true, "whitespace": true, "consecutive_dots": true}',
'{"check_empty_parts": true, "check_whitespace": true, "check_pattern": true}',
'{"check_consecutive_dots": true, "check_chars_strict": false, "allowed_chars": "!--$%&''*+-/=?^_`{|}~."}',
'{"require_dot": true, "check_hyphens": true, "check_consecutive_dots": true, "allowed_chars": ".-"}',
'{"encode_unicode": true, "validate_idna": true}',
'{"basic": "^.+@.+\\..+$", "rfc5322": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)", "local_too_long": "^.{64,}@", "empty_parts": "^@|@$|@\\.|\\.$", "whitespace": "\\s+", "consecutive_dots": "\\.{2,}"}',
'Configuration optimized for international domains and Unicode support',
'2025-04-30T00:00:00Z'
)
ON CONFLICT (name) DO NOTHING;

-- email_filter_regex_settings
CREATE TABLE IF NOT EXISTS email_filter_regex_settings (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nr INTEGER NOT NULL,
    name TEXT NOT NULL UNIQUE,
    main_settings JSONB NOT NULL,
    validation_steps JSONB NOT NULL,
    pattern_checks JSONB NOT NULL,
    format_options JSONB NOT NULL,
    local_part_options JSONB NOT NULL,
    domain_options JSONB NOT NULL,
    idna_options JSONB NOT NULL,
    regex_pattern JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL           
);

INSERT INTO email_filter_regex_settings (nr, name, main_settings, validation_steps, pattern_checks, format_options, local_part_options, domain_options, idna_options, regex_pattern, created_at) VALUES
(
1,     
'Standard Configuration',
'{"strict_mode": false, "max_local_length": 64, "max_domain_length": 255, "max_total_length": 320, "basic_format_pattern": "basic"}',
'{"basic_format": true, "normalization": true, "length_limits": true, "local_part": true, "domain": true, "idna": true}',
'{"empty_parts": true, "whitespace": true, "consecutive_dots": true}',
'{"check_empty_parts": true, "check_whitespace": true, "check_pattern": true}',
'{"check_consecutive_dots": true, "check_chars_strict": true, "allowed_chars": "!--$%&''*+-/=?^_`{|}~."}',
'{"require_dot": true, "check_hyphens": true, "check_chars": true, "check_consecutive_dots": true, "allowed_chars": ".-"}',
'{"encode_unicode": true, "validate_idna": true}',
'{"basic": "^.+@.+\\..+$", "rfc5322": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)", "local_too_long": "^.{64,}@", "empty_parts": "^@|@$|@\\.|\\.$", "whitespace": "\\s+", "consecutive_dots": "\\.{2,}"}',
'2025-04-30T00:00:00Z'
)
ON CONFLICT (name) DO NOTHING;

-- black and white list
CREATE TABLE IF NOT EXISTS black_white (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by TEXT
);

INSERT INTO black_white (domain, category, timestamp, added_by) VALUES
-- Blacklisted domains
('spam-domain.com', 'blacklisted', '2025-04-30T00:00:00Z', 'SpamHaus'),
('malware-site.com', 'blacklisted', '2025-04-30T00:00:00Z', 'Google SafeBrowsing'),
('phishing-example.net', 'blacklisted', '2025-04-30T00:00:00Z', 'PhishTank'),
('ransomware.info', 'blacklisted', '2025-04-30T00:00:00Z', 'Manual Entry'),
('cheap-pharmacy-pills.com', 'blacklisted', '2025-04-30T00:00:00Z', 'SpamCop'),

-- Whitelisted domains
('gmail.com', 'whitelisted', '2025-04-30T00:00:00Z', 'System Default'),
('outlook.com', 'whitelisted', '2025-04-30T00:00:00Z', 'System Default'),
('yahoo.com', 'whitelisted', '2025-04-30T00:00:00Z', 'System Default'),
('protonmail.com', 'whitelisted', '2025-04-30T00:00:00Z', 'System Default'),
('icloud.com', 'whitelisted', '2025-04-30T00:00:00Z', 'System Default'),
('example.com', 'whitelisted', '2025-04-30T00:00:00Z', 'Testing Domain')
ON CONFLICT (domain) DO NOTHING;

-- cache_entries
CREATE TABLE IF NOT EXISTS cache_entries (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'DEFAULT',
    value JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ttl INTEGER DEFAULT 3600,
    UNIQUE (key, category)
);

-- MX infrastructure with trace_id linking
CREATE TABLE IF NOT EXISTS mx_infrastructure (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    email_validation_id INTEGER,
    domain VARCHAR(255) NOT NULL,
    mx_record VARCHAR(255),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    preference INTEGER,
    has_failover BOOLEAN,
    load_balanced BOOLEAN,
    provider_id INTEGER,
    provider_name TEXT,
    is_self_hosted BOOLEAN,
    is_fallback BOOLEAN DEFAULT FALSE,
    ip_addresses JSONB,
    ptr_records JSONB,
    geo_info JSONB,
    whois_summary JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_mx_trace FOREIGN KEY (trace_id) REFERENCES email_validation_records(trace_id)
);

-- IP address details with trace_id linking
CREATE TABLE IF NOT EXISTS mx_ip_addresses (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    mx_infrastructure_id INTEGER,
    ip_address VARCHAR(45) NOT NULL,
    ip_version INTEGER NOT NULL,
    is_private BOOLEAN NOT NULL,
    ptr_record VARCHAR(255),
    country_code VARCHAR(2),
    region VARCHAR(100),
    provider VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_mx_ip_trace FOREIGN KEY (trace_id) REFERENCES email_validation_records(trace_id)
);

-- Validation steps tracking table
CREATE TABLE IF NOT EXISTS validation_steps (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    email VARCHAR(255) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    function_name VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    duration_ms REAL,
    status VARCHAR(50),
    is_success BOOLEAN,
    result JSONB,
    errors TEXT,
    CONSTRAINT fk_validation_steps_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Validation logs table for all operations
CREATE TABLE IF NOT EXISTS validation_logs (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    operation VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    status VARCHAR(50) NOT NULL,
    duration_ms REAL,
    details JSONB,
    CONSTRAINT fk_validation_logs_trace FOREIGN KEY (trace_id) REFERENCES email_validation_records(trace_id)
);

-- Domain-specific SMTP statistics and settings
CREATE TABLE IF NOT EXISTS smtp_domain_stats (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    
    -- Basic statistics
    total_attempts INTEGER DEFAULT 0,
    successful_attempts INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    timeout_count INTEGER DEFAULT 0,
    success_rate NUMERIC(5,2) DEFAULT 0.0,  -- Percentage
    
    -- Timing metrics
    avg_response_time_ms INTEGER DEFAULT 0,
    min_response_time_ms INTEGER DEFAULT 0,
    max_response_time_ms INTEGER DEFAULT 0,
    timeout_adjustment_factor NUMERIC(5,2) DEFAULT 1.0,
    
    -- Retry strategy
    current_backoff_level INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0,
    retry_available_after TIMESTAMPTZ DEFAULT NULL,
    
    -- Regional settings
    country_code VARCHAR(2) DEFAULT NULL,
    region VARCHAR(100) DEFAULT NULL,
    detected_provider VARCHAR(100) DEFAULT NULL,
    
    -- Timestamps
    first_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_success_at TIMESTAMPTZ DEFAULT NULL,
    last_failure_at TIMESTAMPTZ DEFAULT NULL,
    
    -- Settings and flags
    custom_settings JSONB DEFAULT NULL,
    is_problematic BOOLEAN DEFAULT FALSE,

    --error code stats
    last_error_code INTEGER,
    common_error_codes JSONB DEFAULT '{}',
    
    
    UNIQUE(domain)
);

-- Individual attempt history for detailed analysis
CREATE TABLE IF NOT EXISTS smtp_domain_attempt_history (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    email VARCHAR(255) NOT NULL,
    mx_host VARCHAR(255),
    port INTEGER,
    attempt_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    response_time_ms INTEGER,
    success BOOLEAN DEFAULT FALSE,
    error_code INTEGER,
    error_type VARCHAR(50), -- temporary, permanent, timeout, etc.
    trace_id TEXT
);

-- Temp blocked domains
CREATE TABLE IF NOT EXISTS smtp_temporary_blocklist (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    block_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(domain)
);

-- =============================================
-- Functions
-- =============================================

-- A cleanup function for expired temporary blocks
CREATE OR REPLACE FUNCTION clear_expired_temp_blocks()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM smtp_temporary_blocklist WHERE expires_at <= NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function: expire_cache_entries
CREATE OR REPLACE FUNCTION expire_cache_entries()
RETURNS trigger AS $$
BEGIN
    DELETE FROM cache_entries
    WHERE ttl > 0 AND created_at + (ttl * interval '1 second') < NOW();
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function: update_timestamp
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create a function to get the full validation data
CREATE OR REPLACE FUNCTION get_full_validation_data(p_trace_id TEXT)
RETURNS JSONB AS $$
DECLARE
    result JSONB;
BEGIN
    SELECT 
        jsonb_build_object(
            'validation', row_to_json(evr),
            'mx_data', (SELECT jsonb_agg(row_to_json(mi)) FROM mx_infrastructure mi WHERE mi.trace_id = p_trace_id),
            'ip_data', (SELECT jsonb_agg(row_to_json(mip)) FROM mx_ip_addresses mip WHERE mip.trace_id = p_trace_id),
            'steps', (SELECT jsonb_agg(row_to_json(vs)) FROM validation_steps vs WHERE vs.trace_id = p_trace_id),
            'logs', (SELECT jsonb_agg(row_to_json(vl)) FROM validation_logs vl WHERE vl.trace_id = p_trace_id)
        )
    INTO result
    FROM email_validation_records evr
    WHERE evr.trace_id = p_trace_id;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to get domain statistics
CREATE OR REPLACE FUNCTION get_domain_stats(domain_name TEXT)
RETURNS RECORD AS $$
DECLARE
    result RECORD;
BEGIN
    SELECT * INTO result
    FROM smtp_domain_stats 
    WHERE domain = domain_name;
    
    -- If no record exists, create one with defaults
    IF NOT FOUND THEN
        INSERT INTO smtp_domain_stats (domain)
        VALUES (domain_name)
        ON CONFLICT (domain) DO NOTHING;
        
        SELECT * INTO result
        FROM smtp_domain_stats 
        WHERE domain = domain_name;
    END IF;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate success rates
CREATE OR REPLACE FUNCTION calculate_domain_success_rate(domain_name TEXT)
RETURNS NUMERIC AS $$
DECLARE
    success_rate NUMERIC;
BEGIN
    SELECT 
        CASE 
            WHEN total_attempts > 0 THEN 
                ROUND((successful_attempts::NUMERIC / total_attempts) * 100, 2)
            ELSE 0
        END
    INTO success_rate
    FROM smtp_domain_stats
    WHERE domain = domain_name;
    
    RETURN COALESCE(success_rate, 0);
END;
$$ LANGUAGE plpgsql;

-- geographic update 
CREATE OR REPLACE FUNCTION update_domain_geographic_info(
    domain_name TEXT, 
    p_country_code VARCHAR(2) DEFAULT NULL,
    p_region VARCHAR(100) DEFAULT NULL,
    p_provider VARCHAR(100) DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    UPDATE smtp_domain_stats 
    SET 
        country_code = COALESCE(p_country_code, country_code),
        region = COALESCE(p_region, region),
        detected_provider = COALESCE(p_provider, detected_provider)
    WHERE domain = domain_name;
END;
$$ LANGUAGE plpgsql;

-- =============================================
-- Triggers
-- =============================================

-- Trigger: cleanup_expired_cache
CREATE TRIGGER cleanup_expired_cache
AFTER INSERT ON cache_entries
EXECUTE FUNCTION expire_cache_entries();

-- Trigger: update_email_filter_regex_settings_timestamp
CREATE TRIGGER update_email_filter_regex_settings_timestamp
BEFORE UPDATE ON email_filter_regex_settings
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- =============================================
-- Indexes
-- =============================================

-- Email validation records indexes
CREATE INDEX IF NOT EXISTS idx_email_validation_trace_id ON email_validation_records(trace_id);
CREATE INDEX IF NOT EXISTS idx_email_validation_email ON email_validation_records(email);
CREATE INDEX IF NOT EXISTS idx_email_validation_domain ON email_validation_records(domain);
CREATE INDEX IF NOT EXISTS idx_email_validation_timestamp ON email_validation_records(timestamp);

-- MX infrastructure indexes
CREATE INDEX IF NOT EXISTS idx_mx_infrastructure_trace_id ON mx_infrastructure(trace_id);
CREATE INDEX IF NOT EXISTS idx_mx_domain ON mx_infrastructure(domain);
CREATE INDEX IF NOT EXISTS idx_mx_provider_name ON mx_infrastructure(provider_name);
CREATE INDEX IF NOT EXISTS idx_mx_ip_addresses_provider ON mx_ip_addresses(provider);

-- MX IP addresses indexes
CREATE INDEX IF NOT EXISTS idx_mx_ip_addresses_trace_id ON mx_ip_addresses(trace_id);
CREATE INDEX IF NOT EXISTS idx_ip_address ON mx_ip_addresses(ip_address);
CREATE INDEX IF NOT EXISTS idx_country_code ON mx_ip_addresses(country_code);

-- Validation steps and logs indexes
CREATE INDEX IF NOT EXISTS idx_validation_steps_trace ON validation_steps(trace_id);
CREATE INDEX IF NOT EXISTS idx_validation_steps_email ON validation_steps(email);
CREATE INDEX IF NOT EXISTS idx_validation_logs_trace ON validation_logs(trace_id);

-- Other important indexes
CREATE INDEX IF NOT EXISTS idx_func_depends ON email_validation_function_dependencies(function_name, depends_on);
CREATE INDEX IF NOT EXISTS idx_depends_on ON email_validation_function_dependencies(depends_on);
CREATE INDEX IF NOT EXISTS cache_entries_key_category_idx ON cache_entries(key, category);
CREATE INDEX IF NOT EXISTS cache_entries_category_idx ON cache_entries(category);
CREATE INDEX IF NOT EXISTS idx_cache_entries_created_ttl ON cache_entries(created_at, ttl);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_nameserver ON dns_server_stats(nameserver);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_timestamp ON dns_server_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_executor_pool_benchmark_log_run_time ON executor_pool_benchmark_log(run_time DESC);

--SMTP
CREATE INDEX IF NOT EXISTS idx_smtp_domain_stats_domain ON smtp_domain_stats(domain);
CREATE INDEX IF NOT EXISTS idx_smtp_attempt_history_domain ON smtp_domain_attempt_history(domain);
CREATE INDEX IF NOT EXISTS idx_smtp_temp_blocklist_domain ON smtp_temporary_blocklist(domain);
CREATE INDEX IF NOT EXISTS idx_smtp_temp_blocklist_expires ON smtp_temporary_blocklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_smtp_domain_stats_retry_after ON smtp_domain_stats(retry_available_after) WHERE retry_available_after IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_smtp_domain_stats_problematic ON smtp_domain_stats(is_problematic) WHERE is_problematic = TRUE;
CREATE INDEX IF NOT EXISTS idx_smtp_domain_stats_provider ON smtp_domain_stats(detected_provider) WHERE detected_provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_smtp_attempt_history_trace ON smtp_domain_attempt_history(trace_id);
CREATE INDEX IF NOT EXISTS idx_smtp_attempt_history_time ON smtp_domain_attempt_history(attempt_time);
CREATE INDEX IF NOT EXISTS idx_smtp_attempt_history_success ON smtp_domain_attempt_history(success, attempt_time);
-- =============================================
-- View
-- =============================================

-- Validation Pipeline View
CREATE OR REPLACE VIEW validation_pipeline AS
SELECT 
    evr.trace_id,
    evr.email,
    evr.timestamp as validation_time,
    evr.is_valid,
    evr.confidence_score,
    array_agg(DISTINCT vs.step_name) as completed_steps,
    array_agg(DISTINCT mi.id) as mx_infrastructure_ids,
    evr.execution_time,
    b.name as batch_name
FROM email_validation_records evr
LEFT JOIN validation_steps vs ON evr.trace_id = vs.trace_id
LEFT JOIN mx_infrastructure mi ON evr.trace_id = mi.trace_id
LEFT JOIN batch_info b ON evr.batch_id = b.id
GROUP BY evr.trace_id, evr.email, evr.timestamp, evr.is_valid, evr.confidence_score, evr.execution_time, b.name;

-- Create an enhanced view with hit counters
CREATE OR REPLACE VIEW email_provider_mapping AS
SELECT 
    mip.provider AS provider_name,
    mip.ip_address,
    mip.country_code,
    mip.region,
    COUNT(DISTINCT evr.trace_id) AS validation_count,  -- Hit counter
    COUNT(DISTINCT evr.domain) AS domain_count,        -- Unique domains
    MIN(evr.timestamp) AS first_seen,                  -- First appearance
    MAX(evr.timestamp) AS last_seen,                   -- Last appearance
    string_agg(DISTINCT mip.ptr_record, ', ') AS ptr_records
FROM mx_ip_addresses mip
JOIN email_validation_records evr ON mip.trace_id = evr.trace_id
WHERE mip.provider IS NOT NULL
GROUP BY 
    mip.provider,
    mip.ip_address,
    mip.country_code,
    mip.region;

-- An comprehensive email validation statistics
CREATE OR REPLACE VIEW validation_statistics AS
WITH validation_counts AS (
    SELECT
        COUNT(*) AS total_validations,
        COUNT(DISTINCT domain) AS unique_domains,
        COUNT(DISTINCT email) AS unique_emails,
        SUM(CASE WHEN is_valid THEN 1 ELSE 0 END) AS valid_emails,
        AVG(CASE WHEN is_valid THEN confidence_score ELSE 0 END) AS avg_confidence_valid,
        AVG(confidence_score) AS avg_confidence_overall,
        AVG(execution_time) AS avg_execution_time,
        MIN(timestamp) AS earliest_validation,
        MAX(timestamp) AS latest_validation,
        (EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp)))) / 86400 AS days_running
    FROM email_validation_records
),
mx_stats AS (
    SELECT
        COUNT(*) AS total_mx_records,
        SUM(CASE WHEN has_failover THEN 1 ELSE 0 END) AS with_failover,
        SUM(CASE WHEN load_balanced THEN 1 ELSE 0 END) AS load_balanced,
        SUM(CASE WHEN is_self_hosted THEN 1 ELSE 0 END) AS self_hosted,
        COUNT(DISTINCT domain) AS domains_with_mx
    FROM mx_infrastructure
),
geo_stats AS (
    SELECT
        COUNT(DISTINCT country_code) AS unique_countries,
        COUNT(DISTINCT region) AS unique_regions,
        COUNT(DISTINCT provider) AS unique_providers
    FROM mx_ip_addresses
),
country_distribution AS (
    SELECT
        country_code,
        COUNT(*) AS ip_count,
        COUNT(DISTINCT trace_id) AS validation_count
    FROM mx_ip_addresses
    WHERE country_code IS NOT NULL
    GROUP BY country_code
    ORDER BY COUNT(*) DESC
),
region_distribution AS (
    SELECT
        region,
        COUNT(*) AS ip_count
    FROM mx_ip_addresses
    WHERE region IS NOT NULL
    GROUP BY region
    ORDER BY COUNT(*) DESC
),
batch_stats AS (
    SELECT
        COUNT(*) AS total_batches,
        SUM(total_emails) AS batch_total_emails,
        SUM(processed_emails) AS batch_processed_emails,
        SUM(success_count) AS batch_success_count,
        SUM(failed_count) AS batch_failed_count,
        AVG(processed_emails::float / NULLIF(EXTRACT(EPOCH FROM (completed_at - created_at)), 0)) AS avg_emails_per_second
    FROM batch_info
    WHERE completed_at IS NOT NULL
),
system_load AS (
    SELECT
        DATE_TRUNC('hour', timestamp) AS hour_bucket,
        COUNT(*) AS validations_per_hour,
        AVG(execution_time) AS avg_exec_time_per_hour
    FROM email_validation_records
    GROUP BY DATE_TRUNC('hour', timestamp)
    ORDER BY hour_bucket DESC
)
SELECT
    vc.total_validations,
    vc.unique_domains,
    vc.unique_emails,
    vc.valid_emails,
    ROUND(((vc.valid_emails::float / NULLIF(vc.total_validations, 0)) * 100)::numeric, 2) AS success_rate_percent,
    ROUND(vc.avg_confidence_valid::numeric, 2) AS avg_confidence_score_valid,
    ROUND(vc.avg_confidence_overall::numeric, 2) AS avg_confidence_score_overall,
    ROUND(vc.avg_execution_time::numeric, 4) AS avg_execution_time_seconds,
    mx.total_mx_records,
    mx.with_failover,
    mx.load_balanced,
    ROUND(((mx.with_failover::float / NULLIF(mx.total_mx_records, 0)) * 100)::numeric, 2) AS failover_percent,
    ROUND(((mx.load_balanced::float / NULLIF(mx.total_mx_records, 0)) * 100)::numeric, 2) AS load_balanced_percent,
    geo.unique_countries,
    geo.unique_regions,
    geo.unique_providers,
    bs.total_batches,
    bs.batch_total_emails,
    bs.batch_processed_emails,
    bs.batch_success_count,
    bs.batch_failed_count,
    ROUND(bs.avg_emails_per_second::numeric, 2) AS avg_emails_per_second,
    vc.earliest_validation,
    vc.latest_validation,
    vc.days_running,
    (SELECT json_agg(cd) FROM (
        SELECT * FROM country_distribution LIMIT 10
    ) cd) AS top_countries,
    (SELECT json_agg(rd) FROM (
        SELECT * FROM region_distribution LIMIT 10
    ) rd) AS top_regions,
    (SELECT json_agg(sl) FROM (
        SELECT * FROM system_load ORDER BY hour_bucket DESC LIMIT 24
    ) sl) AS recent_system_load
FROM validation_counts vc
CROSS JOIN mx_stats mx
CROSS JOIN geo_stats geo
CROSS JOIN batch_stats bs;

-- view for email provider performance analysis
CREATE OR REPLACE VIEW provider_performance AS
SELECT
    mip.provider,
    COUNT(DISTINCT evr.trace_id) AS total_validations,
    COUNT(DISTINCT evr.domain) AS unique_domains,
    SUM(CASE WHEN evr.is_valid THEN 1 ELSE 0 END) AS valid_emails,
    ROUND(((SUM(CASE WHEN evr.is_valid THEN 1 ELSE 0 END)::float / 
           NULLIF(COUNT(DISTINCT evr.trace_id), 0)) * 100)::numeric, 2) AS success_rate_percent,
    ROUND(AVG(evr.confidence_score)::numeric, 2) AS avg_confidence,
    ROUND(AVG(evr.execution_time)::numeric, 4) AS avg_execution_time,
    COUNT(DISTINCT mip.country_code) AS countries_count,
    COUNT(DISTINCT mip.region) AS regions_count,
    array_agg(DISTINCT mip.country_code) FILTER (WHERE mip.country_code IS NOT NULL) AS countries,
    MIN(evr.timestamp) AS first_seen,
    MAX(evr.timestamp) AS last_seen
FROM mx_ip_addresses mip
JOIN email_validation_records evr ON mip.trace_id = evr.trace_id
WHERE mip.provider IS NOT NULL
GROUP BY mip.provider
ORDER BY total_validations DESC;

-- SMTP-specific performance view
CREATE OR REPLACE VIEW smtp_domain_performance AS
SELECT 
    domain,
    total_attempts,
    successful_attempts,
    failed_attempts,
    success_rate,
    avg_response_time_ms,
    timeout_count,
    consecutive_failures,
    current_backoff_level,
    is_problematic,
    detected_provider,
    country_code,
    region,
    last_success_at,
    last_failure_at,
    retry_available_after,
    CASE 
        WHEN retry_available_after IS NULL OR retry_available_after <= NOW() THEN 'Available'
        ELSE 'In Backoff'
    END AS availability_status,
    CASE 
        WHEN retry_available_after IS NOT NULL AND retry_available_after > NOW() THEN
            EXTRACT(EPOCH FROM (retry_available_after - NOW()))
        ELSE 0
    END AS backoff_remaining_seconds
FROM smtp_domain_stats
ORDER BY total_attempts DESC;

-- Show user e-mail in user_agent_email from users_email
CREATE OR REPLACE VIEW user_agent_email_view AS
SELECT u.email AS user_email, a.value AS user_agent_email
FROM users u
JOIN app_settings a ON a.name = 'user_agent_email';