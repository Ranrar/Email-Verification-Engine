-- Email Verification Engine
-- SQL schema for PostgreSQL

-- Set timezone to UTC globally for consistent timestamp handling
SET timezone = 'UTC';
ALTER DATABASE postgres SET timezone TO 'UTC';
ALTER ROLE postgres SET timezone TO 'UTC';

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
    signup_IP TEXT,
    accepts_EULA BOOLEAN NOT NULL,
    accepts_LICENS BOOLEAN NOT NULL                  
);

-- user settings // To be made later
CREATE TABLE IF NOT EXISTS user_settings (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role TEXT NOT NULL

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
('whois_info', 'WHOIS Information', 'Retrieves domain registration information', 35, true, 'src.engine.functions.mx', 'fetch_whois_info'), --whois.py not done
('smtp_validation', 'SMTP Validation', 'Verifies mailbox existence via SMTP connection', 40, true, 'src.engine.functions.smtp', 'validate_smtp'),
('spf_check', 'SPF Validation', 'Checks Sender Policy Framework records', 50, true, 'src.engine.functions.spf', 'spf_check'),
('dkim_check', 'DKIM Validation', 'Checks DomainKeys Identified Mail status', 60, true, 'src.engine.functions.dkim', 'dkim_check'),
('dmarc_check', 'DMARC Policy', 'Checks Domain-based Message Authentication policy', 70, true, 'src.engine.functions.dmarc', 'dmarc_check'),
('imap_check', 'IMAP Verification', 'Checks if domain has IMAP service', 90, true, 'src.engine.functions.imap', 'imap_check')
-- not implementet yet
-- ('catch_all_check', 'Catch-All Detection', 'Checks if domain accepts all emails', 80, true, 'src.engine.functions.4', '4'),
-- ('pop3_check', 'POP3 Verification', 'Checks if domain has POP3 service', 100, true, 'src.engine.functions.6', '6'),
-- ('disposable_check', 'Disposable Email', 'Checks if email is from disposable email service', 110, true, 'src.engine.engine.7', '7')
ON CONFLICT (function_name) DO NOTHING;

-- Dependency table: email_validation_function_dependencies
CREATE TABLE IF NOT EXISTS email_validation_function_dependencies (
    id SERIAL PRIMARY KEY,
    function_name VARCHAR(255) NOT NULL REFERENCES email_validation_functions(function_name) ON DELETE SET NULL,
    depends_on VARCHAR(255) NOT NULL REFERENCES email_validation_functions(function_name) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (function_name, depends_on)
);

-- Primary validation sequence
INSERT INTO email_validation_function_dependencies (function_name, depends_on) VALUES
('mx_records', 'email_format_resaults'),
('whois_info', 'email_format_resaults'),
('smtp_validation', 'mx_records'),
('spf_check', 'mx_records'),
('dmarc_check', 'mx_records'),
('dkim_check', 'mx_records'),
('imap_check', 'mx_records'),
-- ('catch_all_check', 'smtp_validation'),
-- ('pop3_check', 'mx_records'),
-- ('disposable_check', 'email_format_resaults'),
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
    lastscan TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,            
    email TEXT NOT NULL,
    domain TEXT NOT NULL,
    smtp_result TEXT, -- maby
    smtp_banner TEXT,
    smtp_vrfy TEXT, -- maby
    smtp_supports_tls BOOLEAN,
    smtp_supports_auth BOOLEAN,
    smtp_flow_success BOOLEAN,
    smtp_error_code INTEGER,
    smtp_server_message TEXT,
    port TEXT, -- What port?
    mx_records TEXT,
    mx_ip TEXT,
    mx_preferences TEXT,
    mx_analysis JSONB, -- move to another tabel?
    email_provider_id INTEGER, --move to another tabel?
    email_provider_info JSONB, --maby
    reverse_dns TEXT,
    whois_info TEXT,
    catch_all TEXT,
    imap_status TEXT,
    imap_details JSONB,
    pop3_status TEXT,
    pop3_details JSONB,
    spf_status TEXT,
    spf_details JSONB,
    dkim_status TEXT,
    dkim_details JSONB,
    dmarc_status TEXT,
    dmarc_details JSONB,
    server_policies JSONB,
    disposable TEXT, --change to booleen
    blacklist_info TEXT, -- rename?
    error_message TEXT, --maby What error?
    is_valid BOOLEAN DEFAULT FALSE, -- maby
    confidence_score INTEGER DEFAULT 0,
    execution_time REAL DEFAULT 0,
    timing_details TEXT, -- what detailes?
    check_count INTEGER DEFAULT 1,
    batch_id INTEGER NULL,
    raw_result JSONB, --maby move to own tabel
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
('http', 'user_agent', 'version', '0.4', 'Version for User-Agent'),
('http', 'user_agent', 'url', 'https://github.com/Ranrar/Email-Verification-Engine', 'URL for User-Agent contact'),
-- ('http', 'user_agent', 'email', 'verification@example.com', 'email for User-Agent contact'),
('email', 'defaults', 'sender email', 'EmailVerificationEngine@example.com', 'Default sender email address for SMTP verification'),
('Settings', 'Cache', 'cache purge', '300', 'Seconds between cache check TTL to purge for L1, L2 and L3 cache'),
('Settings', 'Debug', 'Enable', '1', 'Enable Debug menu 1=True 0=False'),
('Settings', 'Start', 'Enable', '0', 'Enable Auto-benchmark during start 1=True 0=False'),
('Database', 'Backup', 'Enable', '1', 'Enable database backup 1=True 0=False'),
('Database', 'Backup', 'Count', '5', 'Number of backups to keep'),
('Database', 'Backup', 'TimeUTC', '02:00', 'Time (UTC) to run backup (HH:MM)')
ON CONFLICT (description) DO NOTHING;

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
('dmarc_found', 5, FALSE, 'Domain has DMARC record'),
('dmarc_strong_policy', 5, FALSE, 'Domain has strong DMARC policy'),
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
CREATE TABLE IF NOT EXISTS  ports (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category     TEXT NOT NULL,
    name         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    priority     INTEGER NOT NULL,
    security     TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    description  TEXT NOT NULL,
    UNIQUE(description)
);


INSERT INTO ports (category, name, port, priority, security, protocol, enabled, description) VALUES
-- SMTP ports
('smtp', 'smtp-relay', 25, 3, 'None or STARTTLS', 'TCP', TRUE, 'No encryption, None/TLS, server-to-server (relay)'),
('smtp', 'smtp-submission', 587, 1, 'STARTTLS', 'TCP', TRUE, 'Encryption with STARTTLS, client-to-server (recommended)'),
('smtp', 'smtps', 465, 2, 'SSL/TLS', 'TCP', TRUE, 'Encryption with SSL/TLS, client-to-server (legacy support)'),
('smtp', 'smtp-alt', 2525, 4, 'STARTTLS', 'TCP', TRUE, 'Alternative SMTP port often used by ESPs (Mailgun, SendGrid)'),
('smtp', 'smtp-dev', 8025, 5, 'None or STARTTLS', 'TCP', FALSE, 'Alternate SMTP submission port for local dev tools (MailHog, Mailpit)'),
('smtp', 'smtp-debug', 1025, 6, 'None', 'TCP', FALSE, 'Debug SMTP port for local testing'),

-- DNS/MX ports
('dns', 'dns-mx', 53, 1, 'None', 'UDP/TCP', TRUE, 'MX record lookup via DNS for mail server hostnames'),
('dns', 'dns-ptr', 53, 2, 'None', 'UDP/TCP', TRUE, 'Reverse DNS (PTR) lookup via DNS for IP-to-domain mapping'),
('dns', 'dns-spf', 53, 3, 'None', 'UDP/TCP', TRUE, 'SPF record lookup via DNS TXT record'),
('dns', 'dns-dkim', 53, 4, 'None', 'UDP/TCP', TRUE, 'DKIM record lookup via DNS TXT record'),
('dns', 'dns-dmarc', 53, 5, 'None', 'UDP/TCP', TRUE, 'DMARC record lookup via DNS TXT record'),
('dns', 'dns-dnsbl', 53, 6, 'None', 'UDP/TCP', TRUE, 'DNSBL lookup for checking spam source listings'),
('dns', 'dnssec', 53, 7, 'DNSSEC', 'UDP/TCP', TRUE, 'DNSSEC validation for signed zone verification'),
('dns', 'dns-tlsa', 53, 8, 'DNSSEC', 'UDP/TCP', TRUE, 'TLSA record lookup for DANE SMTP validation'),

-- WHOIS/RDAP
('whois', 'whois', 43, 1, 'None', 'TCP', TRUE, 'WHOIS lookup via TCP for domain registration details'),
('rdap', 'rdap-https', 443, 2, 'TLS', 'TCP', TRUE, 'RDAP lookup via HTTPS (TLS over TCP) for structured domain registration info'),
('rdap', 'rdap-http', 80, 3, 'None', 'TCP', TRUE, 'RDAP fallback lookup via HTTP for domain registration info'),

-- Authentication and security
('auth', 'smtp-policy-check', 25, 1, 'STARTTLS', 'TCP', TRUE, 'SMTP policy check: banner, STARTTLS/AUTH on port 25'),
('auth', 'smtp-submission-check', 587, 2, 'STARTTLS', 'TCP', TRUE, 'SMTP submission: STARTTLS/AUTH on port 587'),
('auth', 'smtps-check', 465, 3, 'SSL/TLS', 'TCP', TRUE, 'SMTPS: implicit SSL/TLS on port 465'),
('auth', 'spf-dns', 53, 4, 'None', 'UDP/TCP', TRUE, 'SPF lookup: DNS TXT record for SPF validation'),
('auth', 'dkim-dns', 53, 5, 'None', 'UDP/TCP', TRUE, 'DKIM lookup: DNS TXT record for DKIM public key'),
('auth', 'dmarc-dns', 53, 6, 'None', 'UDP/TCP', TRUE, 'DMARC lookup: DNS TXT record for DMARC policy'),
('auth', 'dnssec-check', 53, 7, 'DNSSEC', 'UDP/TCP', TRUE, 'DNSSEC check: validate DNSSEC signatures'),
('auth', 'tls-rpt', 53, 8, 'None', 'UDP/TCP', TRUE, 'TLS-RPT lookup: _smtp._tls TXT record'),
('auth', 'mta-sts', 443, 9, 'HTTPS', 'TCP', TRUE, 'MTA-STS policy fetch over HTTPS'),
('auth', 'tls-cipher-scan', 25, 10, 'STARTTLS', 'TCP', TRUE, 'TLS version & cipher suite probe on port 25'),
('auth', 'mta-sts-report', 443, 11, 'HTTPS', 'TCP', TRUE, 'TLS-RPT report endpoint over HTTPS'),
('auth', 'mta-sts-wellknown', 443, 12, 'HTTPS', 'TCP', TRUE, 'MTA-STS .well-known policy file fetch'),

-- Mail retrieval
('mail', 'smtp-rcpt-test', 25, 1, 'None or STARTTLS', 'TCP', TRUE, 'SMTP - Default port used for RCPT TO and catch-all testing'),
('mail', 'smtp-submission', 587, 2, 'STARTTLS', 'TCP', TRUE, 'SMTP - Submission port with STARTTLS support'),
('mail', 'smtps', 465, 3, 'SSL/TLS', 'TCP', TRUE, 'SMTP - Implicit TLS for secure email submission (legacy support)'),
('mail', 'imap', 143, 4, 'STARTTLS', 'TCP', TRUE, 'IMAP - Default port, typically used with STARTTLS'),
('mail', 'imaps', 993, 5, 'SSL/TLS', 'TCP', TRUE, 'IMAP - Implicit TLS for secure IMAP connections'),
('mail', 'pop3', 110, 6, 'STARTTLS', 'TCP', TRUE, 'POP3 - Default port, typically used with STARTTLS'),
('mail', 'pop3s', 995, 7, 'SSL/TLS', 'TCP', TRUE, 'POP3 - Implicit TLS for secure POP3 connections'),
('mail', 'imap-debug', 1143, 8, 'None', 'TCP', FALSE, 'IMAP debug port for local development/testing'),

-- Autoconfig services
('autoconfig', 'thunderbird-autoconfig', 443, 1, 'HTTPS', 'TCP', TRUE, 'Thunderbird autoconfig endpoint over HTTPS'),
('autodiscover', 'outlook-autodiscover', 443, 2, 'HTTPS', 'TCP', TRUE, 'Outlook/Exchange autodiscover endpoint over HTTPS')
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
    UNIQUE(description)
);
-- maby to meny  or convert all to time?
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
('smtp', 'timeout_connect', 5, TRUE, TRUE, 'Timeout in seconds when establishing a connection'),
('smtp', 'timeout_read', 15, TRUE, TRUE, 'Timeout in seconds when waiting for server response'),
('smtp', 'timeout_overall', 30, TRUE, TRUE, 'Maximum allowed time for the entire operation (connection + communication)'),

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
('dns', 'dkim_lookup', 100, FALSE, TRUE, 'Maximum DKIM record lookups per minute'),

-- DNS timeout settings
('dns', 'lookup_timeout', 5, TRUE, TRUE, 'DNS query timeout in seconds'),
('dns', 'retry_interval', 2, TRUE, TRUE, 'Seconds between retry attempts'),
('dns', 'min_mx_records', 1, FALSE, TRUE, 'Minimum required MX records for domain to be valid'),
('dns', 'max_lookups_per_domain', 20, FALSE, TRUE, 'Maximum DNS lookups per domain per minute'),

-- IMAP: Connection limits
('imap', 'imap_connection_limit_per_min', 5, FALSE, TRUE, 'Maximum IMAP connections per minute per IP'),
('imap', 'imap_concurrent_sessions', 16, FALSE, TRUE, 'Maximum concurrent IMAP sessions per user or IP'),

-- IMAP: Timeout settings
('imap', 'timeout_connect', 5, TRUE, TRUE, 'Timeout in seconds for establishing IMAP connection'),
('imap', 'timeout_login', 10, TRUE, TRUE, 'Timeout in seconds for IMAP login/authentication step'),
('imap', 'timeout_read', 15, TRUE, TRUE, 'Timeout in seconds for reading data from IMAP server'),
('imap', 'timeout_idle', 180, TRUE, TRUE, 'Maximum idle time allowed for an IMAP session'),
('imap', 'connection_timeout', 15, TRUE, TRUE, 'Connection timeout in seconds for the IMAP protocol'),

-- IMAP: Rate-limit protection
('imap', 'max_login_failures_per_min', 3, FALSE, TRUE, 'Maximum failed login attempts per IP per minute'),
('imap', 'block_duration_after_failures', 600, TRUE, TRUE, 'Block duration in seconds after repeated login failures'),

-- IMAP: Caching TTLs
('imap', 'imap_capabilities_cache_ttl', 3600, TRUE, TRUE, 'Cache duration in seconds for IMAP CAPABILITY results'),
('imap', 'imap_starttls_support_cache_ttl', 3600, TRUE, TRUE, 'Cache duration in seconds for IMAP STARTTLS support checks'),

-- POP3: Connection limits
('pop3', 'connection_limit_per_min', 5, FALSE, TRUE, 'Maximum POP3 connections per minute per IP'),
('pop3', 'concurrent_sessions', 16, FALSE, TRUE, 'Maximum concurrent POP3 sessions per user or IP'),

-- POP3: Timeout settings
('pop3', 'timeout_connect', 5, TRUE, TRUE, 'Timeout in seconds for establishing POP3 connection'),
('pop3', 'timeout_login', 10, TRUE, TRUE, 'Timeout in seconds for POP3 login/authentication step'),
('pop3', 'timeout_read', 15, TRUE, TRUE, 'Timeout in seconds for reading data from POP3 server'),
('pop3', 'timeout_idle', 180, TRUE, TRUE, 'Maximum idle time allowed for a POP3 session'),
('pop3', 'connection_timeout', 15, TRUE, TRUE, 'Connection timeout in seconds for the POP3 protocol'),

-- POP3: Rate-limit protection
('pop3', 'max_login_failures_per_min', 3, FALSE, TRUE, 'Maximum failed login attempts per IP per minute'),
('pop3', 'block_duration_after_failures', 600, TRUE, TRUE, 'Block duration in seconds after repeated login failures'),

-- POP3: Caching TTLs (optional – few POP3 servers offer useful CAPABILITY responses, but you can include if applicable)
('pop3', 'pop3_capabilities_cache_ttl', 3600, TRUE, TRUE, 'Cache duration in seconds for POP3 CAPABILITY results'),
('pop3', 'pop3_starttls_support_cache_ttl', 3600, TRUE, TRUE, 'Cache duration in seconds for POP3 STARTTLS support checks')
ON CONFLICT (description) DO NOTHING;

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
('collect_stats', '1', FALSE, 'Whether to collect DNS server performance statistics (1 = yes, 0 = no)'),
('selection_strategy', '3', FALSE, 'DNS server selection strategy (random=1, round_robin=2, best_performer=3)'),
('max_attempts', '3', FALSE, 'Maximum number of attempts when resolving DNS records'),
('max_queries_per_minute', '60', FALSE, 'Maximum DNS queries allowed per minute total'),
('max_queries_per_domain', '5', FALSE, 'Maximum DNS queries allowed per minute for a specific domain'),
('use_edns', '1', FALSE, 'Use EDNS extensions for DNS queries (1 = yes, 0 = no)'),
('fallback_to_tcp', '1', FALSE, 'Fallback to TCP if UDP response is truncated or fails (1 = yes, 0 = no)'),
('use_dnssec', '1', FALSE, 'Enable DNSSEC validation for DNS queries (1 = yes, 0 = no)'),
('edns_payload_size', '1232', TRUE, 'EDNS maximum UDP payload size'),
('prefer_ipv6', '1', FALSE, 'Prefer IPv6 addresses when available (1 = yes, 0 = no)')
ON CONFLICT (name) DO NOTHING;

-- DNS nameserver list

CREATE TABLE dns_nameservers (
    id SERIAL PRIMARY KEY,
    ip_address TEXT NOT NULL UNIQUE,
    version TEXT CHECK (version IN ('IPv4', 'IPv6')) NOT NULL,
    provider TEXT NOT NULL,
    supports_dnssec BOOLEAN DEFAULT TRUE,
    supports_edns BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    description TEXT
);

INSERT INTO dns_nameservers (ip_address, version, provider, supports_dnssec, supports_edns, is_active, priority, description) VALUES
-- Cloudflare
('1.1.1.1',       'IPv4', 'Cloudflare', TRUE, TRUE, TRUE, 100, 'Hurtig, privat DNS'),
('1.0.0.1',       'IPv4', 'Cloudflare', TRUE, TRUE, TRUE, 100, 'Backup Cloudflare DNS'),
('2606:4700:4700::1111', 'IPv6', 'Cloudflare', TRUE, TRUE, TRUE, 100, 'IPv6 primary'),
('2606:4700:4700::1001', 'IPv6', 'Cloudflare', TRUE, TRUE, TRUE, 100, 'IPv6 secondary'),

-- Google DNS
('8.8.8.8',       'IPv4', 'Google DNS', TRUE, TRUE, TRUE, 110, 'Primær Google DNS'),
('8.8.4.4',       'IPv4', 'Google DNS', TRUE, TRUE, TRUE, 110, 'Sekundær Google DNS'),
('2001:4860:4860::8888', 'IPv6', 'Google DNS', TRUE, TRUE, TRUE, 110, 'IPv6 primary'),
('2001:4860:4860::8844', 'IPv6', 'Google DNS', TRUE, TRUE, TRUE, 110, 'IPv6 secondary'),

-- Quad9 Secure
('9.9.9.9',       'IPv4', 'Quad9 Secure', TRUE, TRUE, TRUE, 120, 'Filtrerer malware og phishing'),
('149.112.112.112', 'IPv4', 'Quad9 Secure', TRUE, TRUE, TRUE, 120, 'Backup Quad9'),
('2620:fe::fe',   'IPv6', 'Quad9 Secure', TRUE, TRUE, TRUE, 120, 'IPv6 primary'),
('2620:fe::9',    'IPv6', 'Quad9 Secure', TRUE, TRUE, TRUE, 120, 'IPv6 secondary'),

-- Quad9 Unfiltered
('9.9.9.10',      'IPv4', 'Quad9 Unfiltered', TRUE, TRUE, TRUE, 130, 'Ufiltreret Quad9'),
('2620:fe::10',   'IPv6', 'Quad9 Unfiltered', TRUE, TRUE, TRUE, 130, 'Ufiltreret IPv6'),

-- OpenDNS (Cisco)
('208.67.222.222','IPv4', 'OpenDNS', TRUE, TRUE, TRUE, 140, 'Primær OpenDNS med filtrering'),
('208.67.220.220','IPv4', 'OpenDNS', TRUE, TRUE, TRUE, 140, 'Sekundær OpenDNS'),
('2620:119:35::35','IPv6', 'OpenDNS', TRUE, TRUE, TRUE, 140, 'IPv6 primary'),
('2620:119:53::53','IPv6', 'OpenDNS', TRUE, TRUE, TRUE, 140, 'IPv6 secondary'),

-- AdGuard
('94.140.14.14',  'IPv4', 'AdGuard', TRUE, TRUE, TRUE, 150, 'DNS med reklameblokering'),
('94.140.15.15',  'IPv4', 'AdGuard', TRUE, TRUE, TRUE, 150, 'Backup AdGuard'),
('2a10:50c0::ad1:ff', 'IPv6', 'AdGuard', TRUE, TRUE, TRUE, 150, 'IPv6 primary'),
('2a10:50c0::ad2:ff', 'IPv6', 'AdGuard', TRUE, TRUE, TRUE, 150, 'IPv6 secondary'),

-- CleanBrowsing (Family)
('185.228.168.168','IPv4', 'CleanBrowsing Family', TRUE, TRUE, TRUE, 160, 'Filtrerer voksenindhold og malware'),
('185.228.169.168','IPv4', 'CleanBrowsing Family', TRUE, TRUE, TRUE, 160, 'Backup CleanBrowsing'),
('2a0d:2a00:1::1','IPv6', 'CleanBrowsing Family', TRUE, TRUE, TRUE, 160, 'IPv6 primary'),
('2a0d:2a00:2::1','IPv6', 'CleanBrowsing Family', TRUE, TRUE, TRUE, 160, 'IPv6 secondary'),

-- Comodo Secure DNS
('8.26.56.26',    'IPv4', 'Comodo Secure DNS', FALSE, TRUE, TRUE, 170, 'DNS med malware-beskyttelse'),
('8.20.247.20',   'IPv4', 'Comodo Secure DNS', FALSE, TRUE, TRUE, 170, 'Backup Comodo')
ON CONFLICT (ip_address) DO NOTHING;

-- DNS server statistics table for monitoring performance and reliability
CREATE TABLE IF NOT EXISTS dns_server_stats (
    id SERIAL PRIMARY KEY,
    nameserver TEXT NOT NULL,
    query_type TEXT NOT NULL,
    queries INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    misses INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms FLOAT,
    max_latency_ms FLOAT,
    min_latency_ms FLOAT,
    p50_latency_ms FLOAT,
    p90_latency_ms FLOAT,
    p95_latency_ms FLOAT,
    p99_latency_ms FLOAT,
    since TIMESTAMPTZ NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(nameserver, query_type)
);

CREATE TABLE IF NOT EXISTS dmarc_validation_statistics (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    raw_record TEXT,
    policy VARCHAR(20) NOT NULL,
    policy_strength VARCHAR(20) NOT NULL,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    has_reporting BOOLEAN DEFAULT FALSE,
    alignment_mode VARCHAR(10) DEFAULT 'relaxed',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fk_dmarc_validation_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
);

-- Table for storing DMARC validation history with daily granularity per domain
CREATE TABLE IF NOT EXISTS dmarc_validation_history (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    policy VARCHAR(20) NOT NULL,
    policy_strength VARCHAR(20) NOT NULL,
    alignment_mode VARCHAR(10),
    percentage_covered INTEGER,
    aggregate_reporting BOOLEAN DEFAULT FALSE,
    forensic_reporting BOOLEAN DEFAULT FALSE,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    errors JSONB,
    warnings JSONB,
    recommendations JSONB,
    trace_id TEXT,
    validated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    validation_date DATE DEFAULT CURRENT_DATE,
    last_validated_at TIMESTAMPTZ,
    CONSTRAINT unique_domain_daily UNIQUE(domain, validation_date),
    CONSTRAINT fk_dmarc_validation_history_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
);

-- Detailed DKIM validation results
CREATE TABLE IF NOT EXISTS dkim_validation_statistics (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    selector TEXT,
    raw_record TEXT,
    has_dkim BOOLEAN DEFAULT FALSE,
    key_type TEXT,
    key_length INTEGER,
    security_level TEXT,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    errors TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_dkim_validation_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
);

-- IMAP validation statistics table
CREATE TABLE IF NOT EXISTS imap_validation_statistics (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    has_imap BOOLEAN DEFAULT FALSE,
    servers_found INTEGER DEFAULT 0,
    security_level VARCHAR(20),
    supports_ssl BOOLEAN DEFAULT FALSE,
    supports_starttls BOOLEAN DEFAULT FALSE,
    supports_oauth BOOLEAN DEFAULT FALSE,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    errors TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_imap_validation_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
);

-- IMAP validation history table
CREATE TABLE IF NOT EXISTS imap_validation_history (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    has_imap BOOLEAN DEFAULT FALSE,
    servers_found INTEGER DEFAULT 0,
    security_level VARCHAR(20),
    supports_ssl BOOLEAN DEFAULT FALSE,
    supports_starttls BOOLEAN DEFAULT FALSE,
    supports_oauth BOOLEAN DEFAULT FALSE,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    errors JSONB,
    warnings JSONB,
    recommendations JSONB,
    trace_id TEXT,
    validated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    validation_date DATE DEFAULT CURRENT_DATE,
    last_validated_at TIMESTAMPTZ,
    CONSTRAINT unique_domain_daily_imap UNIQUE(domain, validation_date),
    CONSTRAINT fk_imap_validation_history_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
);

-- Table for storing DKIM validation history with daily granularity per domain
CREATE TABLE IF NOT EXISTS dkim_validation_history (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    selector VARCHAR(100) NOT NULL,
    has_dkim BOOLEAN DEFAULT FALSE,
    key_type VARCHAR(20),
    key_length INTEGER,
    security_level VARCHAR(20),
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    errors JSONB,
    warnings JSONB,
    recommendations JSONB,
    trace_id TEXT,
    validated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    validation_date DATE DEFAULT CURRENT_DATE,
    last_validated_at TIMESTAMPTZ,
    CONSTRAINT unique_domain_selector_daily UNIQUE(domain, selector, validation_date),
    CONSTRAINT fk_dkim_history_trace FOREIGN KEY (trace_id)
        REFERENCES email_validation_records(trace_id)
        ON DELETE SET NULL
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
    nr INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    main_settings JSONB NOT NULL,
    validation_steps JSONB NOT NULL,
    pattern_checks JSONB NOT NULL,
    format_options JSONB NOT NULL,
    local_part_options JSONB NOT NULL,
    domain_options JSONB NOT NULL,
    idna_options JSONB NOT NULL,
    regex_pattern JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO email_filter_regex_settings (nr, name, main_settings, validation_steps, pattern_checks, format_options, local_part_options, domain_options, idna_options, regex_pattern, description, created_at) VALUES (
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
    'Standard email validation configuration based on RFC standards',
    '2025-04-30T00:00:00Z'
)
ON CONFLICT (nr) DO NOTHING;


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

-- Detailed SPF validation results
CREATE TABLE IF NOT EXISTS spf_validation_statistics (
    id SERIAL PRIMARY KEY,
    trace_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    raw_record TEXT,
    result TEXT NOT NULL,
    mechanism_matched TEXT,
    dns_lookups INTEGER DEFAULT 0,
    processing_time_ms FLOAT,
    explanation TEXT,
    error_message TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_spf_validation_trace FOREIGN KEY (trace_id) 
        REFERENCES email_validation_records(trace_id)
);

-- Detailed DNS lookup tracking for SPF mechanisms
CREATE TABLE IF NOT EXISTS spf_dns_lookup_log (
    id SERIAL PRIMARY KEY,
    spf_validation_id INTEGER NOT NULL,
    mechanism TEXT NOT NULL,
    lookups_used INTEGER NOT NULL,
    total_lookups INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_spf_dns_lookup_validation FOREIGN KEY (spf_validation_id) 
        REFERENCES spf_validation_statistics(id)
);

-- Table for storing Public Suffix List entries
CREATE TABLE IF NOT EXISTS public_suffix_list (
    id SERIAL PRIMARY KEY,
    suffix TEXT NOT NULL,              -- The domain suffix itself (e.g., "com.ac")
    is_wildcard BOOLEAN DEFAULT FALSE, -- Whether it's a wildcard entry (e.g., "*.ck")
    is_exception BOOLEAN DEFAULT FALSE,-- Whether it's an exception entry (e.g., "!www.ck")
    category TEXT NOT NULL,            -- 'ICANN' or 'PRIVATE' domain
    country_code TEXT,                 -- Country code if applicable (e.g., "ac" for Ascension Island)
    organization TEXT,                 -- Organization maintaining the domain
    source_url TEXT,                   -- Source URL mentioned in comments
    description TEXT,                  -- Additional information from comments
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(suffix)
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_public_suffix_list_suffix ON public_suffix_list(suffix);
CREATE INDEX IF NOT EXISTS idx_public_suffix_list_category ON public_suffix_list(category);
CREATE INDEX IF NOT EXISTS idx_public_suffix_list_country ON public_suffix_list(country_code);

-- Version tracking table to manage updates from the official source
CREATE TABLE IF NOT EXISTS public_suffix_list_version (
    id SERIAL PRIMARY KEY,
    version TEXT,
    import_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    source_url TEXT NOT NULL DEFAULT 'https://publicsuffix.org/list/public_suffix_list.dat',
    entry_count INTEGER NOT NULL
);

-- Function to update timestamp when record is updated
CREATE OR REPLACE FUNCTION update_psl_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update timestamp
CREATE TRIGGER update_public_suffix_list_timestamp
BEFORE UPDATE ON public_suffix_list
FOR EACH ROW EXECUTE FUNCTION update_psl_timestamp();

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

-- Calculate domain success rate function -- not implemenet yet!
CREATE OR REPLACE FUNCTION calculate_domain_success_rate(domain_name TEXT)
RETURNS TABLE (
    success_rate NUMERIC(5,2),
    total_attempts INTEGER,
    successful_attempts INTEGER,
    avg_response_time_ms INTEGER,
    is_problematic BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        CASE 
            WHEN s.total_attempts > 0 THEN 
                (s.successful_attempts::NUMERIC / s.total_attempts::NUMERIC) * 100.0
            ELSE 0.0
        END AS success_rate,
        s.total_attempts,
        s.successful_attempts,
        s.avg_response_time_ms,
        s.is_problematic
    FROM smtp_domain_stats s
    WHERE s.domain = domain_name;
    
    -- Return empty record if no stats found
    IF NOT FOUND THEN
        RETURN QUERY SELECT 0.0::NUMERIC(5,2), 0, 0, 0, FALSE;
    END IF;
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
CREATE INDEX IF NOT EXISTS idx_email_validation_dkim_status ON email_validation_records(dkim_status);
CREATE INDEX IF NOT EXISTS idx_email_validation_dkim_details ON email_validation_records USING GIN (dkim_details);

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
CREATE INDEX IF NOT EXISTS idx_executor_pool_benchmark_log_run_time ON executor_pool_benchmark_log(run_time DESC);

--DNS
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_nameserver ON dns_server_stats(nameserver);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_nameserver_query_type ON dns_server_stats(nameserver, query_type);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_timestamp ON dns_server_stats(since);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_agg_nameserver ON dns_server_stats(nameserver);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_agg_query_type ON dns_server_stats(query_type);
CREATE INDEX IF NOT EXISTS idx_dns_server_stats_agg_last_updated ON dns_server_stats(last_updated);

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

--SPF
CREATE INDEX IF NOT EXISTS idx_spf_validation_trace_id ON spf_validation_statistics(trace_id);
CREATE INDEX IF NOT EXISTS idx_spf_validation_domain ON spf_validation_statistics(domain);
CREATE INDEX IF NOT EXISTS idx_spf_validation_result ON spf_validation_statistics(result);
CREATE INDEX IF NOT EXISTS idx_spf_dns_lookup_validation ON spf_dns_lookup_log(spf_validation_id);

--DMARC
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_stats_domain ON dmarc_validation_statistics(domain);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_stats_trace_id ON dmarc_validation_statistics(trace_id);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_stats_created_at ON dmarc_validation_statistics(created_at);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_history_domain ON dmarc_validation_history(domain);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_history_policy ON dmarc_validation_history(policy);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_history_strength ON dmarc_validation_history(policy_strength);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_history_trace ON dmarc_validation_history(trace_id);
CREATE INDEX IF NOT EXISTS idx_dmarc_validation_history_date ON dmarc_validation_history(validated_at);

-- DKIM
CREATE INDEX IF NOT EXISTS idx_dkim_validation_stats_domain ON dkim_validation_statistics(domain);
CREATE INDEX IF NOT EXISTS idx_dkim_validation_stats_trace_id ON dkim_validation_statistics(trace_id);
CREATE INDEX IF NOT EXISTS idx_dkim_validation_stats_created_at ON dkim_validation_statistics(created_at);

-- IMAP
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_trace_id ON imap_validation_statistics(trace_id);
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_domain ON imap_validation_statistics(domain);
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_created_at ON imap_validation_statistics(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_domain_created ON imap_validation_statistics(domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_has_imap_security ON imap_validation_statistics(has_imap, security_level) WHERE has_imap = true;
CREATE INDEX IF NOT EXISTS idx_imap_validation_statistics_processing_time ON imap_validation_statistics(processing_time_ms DESC) WHERE processing_time_ms > 1000;

CREATE INDEX IF NOT EXISTS idx_imap_validation_history_domain ON imap_validation_history(domain);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_validation_date ON imap_validation_history(validation_date DESC);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_trace_id ON imap_validation_history(trace_id);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_domain_date ON imap_validation_history(domain, validation_date DESC);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_validated_at ON imap_validation_history(validated_at DESC);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_security_level ON imap_validation_history(security_level) WHERE security_level IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_has_imap ON imap_validation_history(has_imap, validation_date DESC) WHERE has_imap = true;
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_errors_gin ON imap_validation_history USING GIN(errors);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_warnings_gin ON imap_validation_history USING GIN(warnings);
CREATE INDEX IF NOT EXISTS idx_imap_validation_history_recommendations_gin ON imap_validation_history USING GIN(recommendations);


-- =============================================
-- View
-- =============================================

-- View for DMARC trend analysis
CREATE OR REPLACE VIEW dmarc_policy_analysis AS
SELECT 
    d.domain,
    d.policy,
    d.policy_strength,
    d.alignment_mode,
    d.percentage_covered,
    d.aggregate_reporting,
    d.forensic_reporting,
    d.dns_lookups,
    d.processing_time_ms,
    COUNT(*) OVER (PARTITION BY d.domain) as validation_count,
    FIRST_VALUE(d.validated_at) OVER (PARTITION BY d.domain ORDER BY d.validated_at DESC) as last_validation,
    FIRST_VALUE(d.validated_at) OVER (PARTITION BY d.domain ORDER BY d.validated_at ASC) as first_validation,
    CASE 
        WHEN d.policy = 'reject' AND d.percentage_covered = 100 THEN 'Excellent'
        WHEN d.policy = 'quarantine' AND d.percentage_covered >= 75 THEN 'Good'
        WHEN d.policy = 'none' OR d.percentage_covered < 50 THEN 'Needs Improvement'
        ELSE 'Fair'
    END as security_rating
FROM dmarc_validation_history d
ORDER BY d.domain, d.validated_at DESC;

-- View for DKIM trend analysis
CREATE OR REPLACE VIEW dkim_security_analysis AS
SELECT 
    d.domain,
    d.selector,
    d.has_dkim,
    d.key_type,
    d.key_length,
    d.security_level,
    d.dns_lookups,
    d.processing_time_ms,
    COUNT(*) OVER (PARTITION BY d.domain, d.selector) as validation_count,
    FIRST_VALUE(d.validated_at) OVER (PARTITION BY d.domain, d.selector ORDER BY d.validated_at DESC) as last_validation,
    FIRST_VALUE(d.validated_at) OVER (PARTITION BY d.domain, d.selector ORDER BY d.validated_at ASC) as first_validation,
    CASE 
        WHEN d.key_type = 'ed25519' OR (d.key_type = 'rsa' AND d.key_length >= 2048) THEN 'Excellent'
        WHEN d.key_type = 'rsa' AND d.key_length >= 1024 THEN 'Good'
        WHEN d.has_dkim = false THEN 'Missing'
        ELSE 'Weak'
    END as key_rating
FROM dkim_validation_history d
ORDER BY d.domain, d.selector, d.validated_at DESC;

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

-- SPF statistics aggregation view
CREATE OR REPLACE VIEW spf_statistics AS
WITH domain_stats AS (
    SELECT
        domain,
        COUNT(*) AS total_validations,
        SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) AS pass_count,
        SUM(CASE WHEN result = 'fail' THEN 1 ELSE 0 END) AS fail_count,
        SUM(CASE WHEN result = 'softfail' THEN 1 ELSE 0 END) AS softfail_count,
        SUM(CASE WHEN result = 'neutral' THEN 1 ELSE 0 END) AS neutral_count,
        SUM(CASE WHEN result = 'none' THEN 1 ELSE 0 END) AS none_count,
        SUM(CASE WHEN result = 'permerror' THEN 1 ELSE 0 END) AS permerror_count,
        SUM(CASE WHEN result = 'temperror' THEN 1 ELSE 0 END) AS temperror_count,
        AVG(dns_lookups) AS avg_dns_lookups,
        AVG(processing_time_ms) AS avg_processing_time_ms,
        MAX(processing_time_ms) AS max_processing_time_ms,
        MIN(processing_time_ms) AS min_processing_time_ms
    FROM spf_validation_statistics
    GROUP BY domain
),
mechanism_stats AS (
    SELECT
        domain,
        mechanism_matched,
        COUNT(*) AS match_count
    FROM spf_validation_statistics
    WHERE mechanism_matched IS NOT NULL
    GROUP BY domain, mechanism_matched
)
SELECT
    ds.domain,
    ds.total_validations,
    ds.pass_count,
    ds.fail_count,
    ds.softfail_count,
    ds.neutral_count,
    ds.none_count,
    ds.permerror_count,
    ds.temperror_count,
    ROUND(((ds.pass_count::float / NULLIF(ds.total_validations, 0)) * 100)::numeric, 2) AS pass_percentage,
    ROUND(ds.avg_dns_lookups::numeric, 2) AS avg_dns_lookups,
    ROUND(ds.avg_processing_time_ms::numeric, 2) AS avg_processing_time_ms,
    ds.max_processing_time_ms,
    ds.min_processing_time_ms,
    (
        SELECT jsonb_agg(jsonb_build_object(
            'mechanism', mechanism_matched,
            'count', match_count
        ))
        FROM mechanism_stats ms
        WHERE ms.domain = ds.domain
    ) AS top_mechanisms
FROM domain_stats ds
ORDER BY ds.total_validations DESC;