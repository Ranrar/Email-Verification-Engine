# Email Verification Engine

[![CodeQL Advanced](https://github.com/Ranrar/Email-Verification-Engine/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ranrar/Email-Verification-Engine/actions/workflows/codeql.yml)

<pre lang="text">
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░</pre>

## Overview

The Email Verification Engine (EVE) is a robust, modular system designed for high-performance and scalable email validation. It combines advanced syntax checks, DNS and SMTP validation, security policy analysis (SPF, DKIM, DMARC), and disposable/blacklist detection. EVE uses a multi-layered caching strategy—combining in-memory (RAM), local disk (SQLite3), and distributed (PostgreSQL) caches—to maximize speed and efficiency while supporting distributed deployments.

## Features

The system features a `multi-layered caching` architecture that combines in-memory (RAM, TTLCache), local disk (SQLite3 via diskcache), and distributed (PostgreSQL) caches to ensure optimal speed and persistence. A `centralized configuration` approach manages all cache, rate limit, and operational settings via database tables like `cache_settings`, `app_settings`, and `rate_limit`, enabling dynamic tuning without modifying the code. The `validation engine` orchestrates syntax, DNS, SMTP, blacklist, disposable, and security checks through a modular framework, providing detailed scoring and result aggregation. A dedicated `flow manager` oversees batch and parallel validation jobs, tracks job progress, and caches results to handle high-throughput workloads. The `authentication & security manager` performs SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and server policy checks, caching results for efficiency. Complementing this is the `additional protocols manager`, which evaluates IMAP, POP3, and catch-all status with secure protocol checks, parallel execution, and rate limiting. The `DNS manager` supports advanced resolution, nameserver performance tracking, prefetching, and adaptive rate limiting. A centralized `port manager` governs all protocol ports (SMTP, DNS, WHOIS, IMAP, POP3, etc.) with dynamic configurations pulled from the database. The `rate limit manager` offers fine-grained, per-resource and per-category control, storing limits and durations in the database and caching them for speed. A configurable `scoring system` defines validation weights and confidence levels. `Performance monitoring` captures timing and metrics across all operations and supports self-tuning via `auto-tuning` of threads and processes based on live benchmarks. The platform also includes `full logging & stats` for centralized monitoring and debugging, and is fully `extensible & modular`, designed with dependency injection to support custom workflows and integrations.

EVE is suitable for integration into SaaS platforms, bulk validation tools, security-focused email workflows, and distributed environments.

## Installation

1. **Create the PostgreSQL database**  
   Use the `postgres.yaml` and `install.py` in `functions/sql` for configuration.

2. **Register the database in pgAdmin**  
   - Use the same name as `POSTGRES_DB` in your environment.
   - Fill out the required fields under the connection tab.

3. **Install the schema**  
   - Run the installer script:    
   - python> `install.py`
   - This will create all required tables