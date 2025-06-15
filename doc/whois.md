# WHOIS Protocol

## Overview

WHOIS is a protocol used to query databases that store registered users and assignees of internet resources — including domain names, IP address blocks, and autonomous systems.

---

## Purpose

- Retrieves information about a domain's ownership, registrar, registration dates, and name server configuration.
- Commonly used for domain verification, abuse reporting, and legal purposes.

---

## Typical Information Returned

- **Registrant Organization**
- **Registrar Name**
- **Creation Date**
- **Expiration Date**
- **Name Servers**
- **Status** (e.g., clientTransferProhibited)
- **Contact Email or Abuse Contact**

---

## How It Works

1. A WHOIS query is made to a WHOIS server (e.g., `whois.verisign-grs.com`).
2. The server returns text-based details about the resource.
3. In the case of domains, queries may be redirected to registrar-specific WHOIS servers.

---

## Privacy & Redaction

- Many registrars use **WHOIS privacy** or **redaction** due to GDPR and local laws.
- Public access may be limited to non-personal data (e.g., only registrar + status).

---

## WHOIS vs RDAP

- WHOIS is being gradually replaced by **RDAP** (Registration Data Access Protocol).
- RDAP uses JSON format and supports secure access, filtering, and authentication.

---

## Use Cases

- Domain investigation and transfer validation.
- Identifying abuse contacts for reporting spam/phishing.
- Analyzing registration patterns and DNS data.
