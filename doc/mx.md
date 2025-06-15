# Mail Exchange (MX) Records

## Overview

MX records are DNS (Domain Name System) entries that specify the mail servers responsible for receiving email on behalf of a domain. Each record points to a mail server and includes a priority value to determine delivery order.

---

## Purpose

- Directs incoming mail traffic for a domain to the correct mail server(s).
- Supports redundancy and load balancing via multiple entries with different priorities.

---

## Structure

An MX record has two main components:

- **Priority**: A numeric value — lower values are higher priority.
- **Mail Server Hostname**: The FQDN (Fully Qualified Domain Name) of the target server.

**Example:**
example.com. IN MX 10 mail1.example.com.
example.com. IN MX 20 mail2.backup.com.

---

## Resolution Process

1. A sending mail server queries DNS for MX records of the recipient domain.
2. The list is ordered by priority (lowest first).
3. The sender attempts delivery starting from the highest-priority server.
4. If delivery fails, it tries the next one.

---

## Considerations

- Mail servers **must** have corresponding A or AAAA records — not CNAMEs.
- Best practice is to have multiple MX records for redundancy.
- MX records affect deliverability and must be maintained carefully.

---

## Related Concepts

- **SPF** uses MX mechanism to validate if a sender IP is an MX host.
- **PTR / Reverse DNS** should resolve to match outbound server names.

