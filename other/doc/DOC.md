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

The Email Verification Engine (EVE) is a robust, modular system for high-performance, scalable email validation. It combines advanced syntax checks, DNS and SMTP validation, security policy analysis (SPF, DKIM, DMARC), and disposable/blacklist detection. EVE uses a multi-layered caching strategy—combining in-memory (RAM), local disk (SQLite3), and distributed (PostgreSQL) caches—for maximum speed and efficiency.

## Key Features & Functions

- **Multi-layered Caching**  
  Combines RAM, disk, and PostgreSQL caches for fast, persistent, and distributed validation.

- **Centralized Configuration**  
  All settings (cache, rate limits, operational) are managed in the database for live tuning.

- **Validation Engine**  
  Orchestrates modular checks:
  - **Syntax & Format Check**: Validates email structure and syntax.
  - **DNS Validation**: Confirms domain existence and MX records.
  - **SMTP Validation**: Connects to mail servers to verify deliverability.
  - **Blacklist/Disposable Detection**: Flags known bad or temporary domains.
  - **Security Checks**: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and server policy analysis.

- **Batch & Parallel Processing**  
  Flow manager supports bulk validation jobs, parallel execution, and job progress tracking.

- **Authentication & Security Manager**  
  Handles advanced email security protocol checks and caches results for efficiency.

- **Additional Protocols Manager**  
  Supports IMAP, POP3, and catch-all detection with secure protocol checks and rate limiting.

- **DNS Manager**  
  Advanced DNS resolution, nameserver performance tracking, and adaptive rate limiting.

- **Port Manager**  
  Centralized management of protocol ports (SMTP, DNS, WHOIS, IMAP, POP3, etc.) with dynamic configuration.

- **Rate Limit Manager**  
  Fine-grained, per-resource and per-category rate limiting, with durations and limits stored in the database.

- **Scoring System**  
  Configurable scoring and confidence levels for validation results.

- **Performance Monitoring & Auto-tuning**  
  Tracks timing and metrics, with self-tuning of threads and processes based on live benchmarks.

- **Logging & Statistics**  
  Centralized logging, statistics, and debugging tools.

- **Extensible & Modular**  
  Designed for easy integration, customization, and extension via dependency injection.

## Use Cases

- SaaS email validation platforms
- Bulk email list cleaning tools
- Security-focused email workflows
- Distributed and high-throughput environments

## Installation

1. **Create the PostgreSQL database**  
   - Create a `postgres 16` database with `PgAgent`
   - Need help? read my guide here: `other/PostgresGuide.md`

2. **Install the schema**  
   - Run the installer script:  
     `python install.py` from src/database
   - This will create all required tables.

3. **Run**
   py main.py