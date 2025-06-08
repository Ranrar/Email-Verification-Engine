# Email Verification Engine

[![CodeQL Advanced](https://github.com/Ranrar/Email-Verification-Engine/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ranrar/Email-Verification-Engine/actions/workflows/codeql.yml)
[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-yellow.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/)
[![DO NOT USE COMMERCIALLY](https://img.shields.io/badge/Commercial%20Use-Not%20Allowed-red.svg)](mailto:kim@skovrasmussen.com)

<pre lang="text">
 ██████████  █████   █████  ██████████
░░███░░░░░█ ░░███   ░░███  ░░███░░░░░█  
 ░███  █ ░   ░███    ░███   ░███  █ ░
 ░██████     ░███    ░███   ░██████
 ░███░░█     ░░███   ███    ░███░░█
 ░███ ░   █   ░░░█████░     ░███ ░   █
 ██████████     ░░███       ██████████
░░░░░░░░░░       ░░░       ░░░░░░░░░░</pre>

> **Development Status**: This project is currently under active development. Core validation features are functional, but some advanced features are still being implemented. See [Roadmap.md](Roadmap.md) for current development status and planned features.

## Overview

**Email Verification Engine (EVE)** is a comprehensive email validation platform that goes beyond simple format checking. Built for developers and marketing professionals who demand accuracy and performance, EVE combines multiple validation layers to deliver enterprise-grade email verification.

### **What Makes EVE Different**

- **Deep Validation** - Multi-layer verification including syntax, DNS, SMTP, and security protocol analysis
- **High Performance** - Parallel processing with intelligent caching for maximum speed
- **Security Focused** - SPF, DKIM, DMARC validation plus blacklist and disposable email detection
- **Smart Analytics** - Real-time metrics, confidence scoring, and validation insights
- **Developer Ready** - RESTful API, webhooks, and extensible architecture for custom integrations

### **Built for Scale**
EVE handles everything from single email validation to processing millions of addresses with automatic rate limiting, queue management, and resource optimization.

## Use Cases

### **Email Marketing Operations**
- **List Hygiene**: Clean databases before campaigns to improve deliverability rates
- **Sender Reputation**: Protect your domain reputation by removing harmful addresses
- **Campaign ROI**: Reduce bounce rates and improve engagement metrics
- **Compliance**: Meet GDPR and CAN-SPAM requirements with validated contact data

### **Application Security & UX**
- **User Registration**: Block fake signups and disposable emails during account creation
- **Form Validation**: Real-time validation for better user experience
- **Fraud Prevention**: Identify suspicious patterns and temporary email services
- **Data Quality**: Maintain clean user databases with ongoing validation

### **Enterprise & API Integration**
- **CRM Integration**: Validate leads and contacts as they enter your system
- **Webhook Processing**: Real-time validation callbacks for automated workflows
- **Batch Processing**: Handle large datasets with progress tracking and reporting
- **Custom Workflows**: Build validation into existing business processes

### **Compliance & Data Governance**
- **Data Quality Assurance**: Maintain accurate customer databases
- **Regulatory Compliance**: Support GDPR data quality requirements
- **Audit Trails**: Complete validation history and decision logging
- **Risk Management**: Identify and flag high-risk email patterns

---

## Why Choose EVE?

### **Performance That Scales**
- **Multi-threaded Processing**: Parallel validation across CPU cores
- **Intelligent Caching**: Three-tier caching system reduces redundant checks
- **Rate Limiting**: Respectful validation that won't overwhelm mail servers
- **Auto-optimization**: Self-tuning algorithms adapt to your usage patterns

### **Validation Depth**
Unlike basic validators, EVE performs:
- **Syntax Analysis**: RFC 5322 compliance with custom pattern support
- **DNS Resolution**: MX record validation with IPv4/IPv6 dual-stack support
- **SMTP Verification**: Actual mailbox existence checking
- **Security Protocols**: SPF/DKIM/DMARC policy analysis
- **Reputation Checking**: Real-time blacklist and disposable email detection

### **Developer Experience**
- **Modern Web Interface**: Intuitive dashboard with real-time updates
- **Complete API**: RESTful endpoints for seamless integration
- **Extensible Architecture**: Plugin system for custom validation rules
- **Comprehensive Logging**: Detailed analytics and debugging information

### **Enterprise Security**
- **No Data Retention**: Email content never stored, only validation metadata
- **Secure Communications**: TLS encryption for all external connections
- **Audit Logging**: Complete activity tracking for compliance
- **Role-based Access**: Configurable permissions and user management

---

## Technical Highlights

**Architecture**: Modular Python application with PostgreSQL backend  
**Caching**: Multi-layer (RAM/SQLite/PostgreSQL) for optimal performance  
**Protocols**: SMTP, DNS, WHOIS, IMAP, POP3 with security protocol analysis  
**Scalability**: Parallel processing with dynamic resource allocation  
**Integration**: RESTful API, webhooks, CSV/Excel import/export  

**Perfect for:** Development teams building email-dependent applications, marketing operations requiring high-quality data, and enterprises needing scalable validation infrastructure.

---

## Installation

<details>
<summary><strong>Quick Installation Guide</strong></summary>

### **Prerequisites**
- Python 3.11 or higher
- PostgreSQL 16 with PgAgent
- 4GB RAM minimum (8GB recommended)
- Modern web browser

### **Step-by-Step Setup**

1. **Database Preparation**
   ```bash
   # Create PostgreSQL database
   createdb email_verification_engine
   
   # Verify connection
   psql -d email_verification_engine -c "SELECT version();"
   ```

2. **Application Installation**
   ```bash
   # Clone or download the application
   git clone https://github.com/Ranrar/Email-Verification-Engine.git
   cd Email-Verification-Engine
   
   # Install Python dependencies
   pip install -r requirements.txt
   ```

3. **Database Connection and Schema Setup**
   ```bash
   # Navigate to database directory
   cd src/database
   
   # Run the automated installer
   python install.py
   ```

4. **Launch Application**
   ```bash
   # Start the application
   python main.py
   ```
   The web interface will automatically open at `http://localhost:8080`

### **Configuration**
- Database connection settings are configured during the installation process
- System settings can be adjusted via the web interface
- Advanced configuration options are available in the settings panel

</details>

## Documentation

| Resource | Description |
|----------|-------------|
| [`doc/PostgresGuide.md`](doc/PostgresGuide.md) | Complete database setup and configuration |
| [`doc/Regex.md`](doc/Regex.md) | Custom validation patterns and rules |
| [`Roadmap.md`](Roadmap.md) | Development status and upcoming features |
| [`SECURITY.md`](SECURITY.md) | Security policies and vulnerability reporting |
| [`LICENSE.md`](LICENSE.md) | License terms and commercial usage |

## Development Status

**Current Phase**: Active Development - Core features implemented, advanced features in progress

See [`Roadmap.md`](Roadmap.md) for detailed development timeline and planned features.

## Support & Info

- **Technical Questions**: Create an issue on GitHub
- **Development Updates**: Follow the repository for latest changes

## License

This software is licensed under **CC BY-NC-ND 4.0** for non-commercial use.  
Commercial licensing available - contact: kim@skovrasmussen.com

**Email Verification Engine © 2025 Kim Skov Rasmussen**

---

*Ready to improve your email data quality? Contact us to discuss your validation requirements and explore licensing options.*