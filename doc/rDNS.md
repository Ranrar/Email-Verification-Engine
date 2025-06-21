# Reverse DNS (rDNS)

## Overview
Reverse DNS is the process of resolving an IP address back to its associated domain name. Unlike standard DNS, which translates domain names to IPs, reverse DNS queries ask: "What is the domain name for this IP?"

## Purpose
- **Network troubleshooting:** Identifying the hostnames associated with IP addresses.
- **Spam filtering:** Many mail servers check reverse DNS entries to verify the legitimacy of sending servers.
- **Logging and security:** Helps administrators understand where traffic originates from by resolving IP addresses in logs.

## How Reverse DNS Works
Reverse DNS uses special domains under the `.arpa` top-level domain to organize IP addresses for lookup:
- **IPv4:** Uses the `in-addr.arpa` domain. The IP address octets are reversed and appended to `in-addr.arpa`.  
  Example: `192.0.2.1` becomes `1.2.0.192.in-addr.arpa`.
- **IPv6:** Uses the `ip6.arpa` domain. Each hexadecimal digit of the full 128-bit IPv6 address is reversed and separated by dots.

## Implementation
To implement reverse DNS, network operators set up **PTR records** in their DNS zones (see PTR section). The owner of the IP address block typically controls the reverse DNS entries.

## Limitations
- Reverse DNS entries are optional and not always configured.
- An IP can have multiple domain names, but reverse DNS only maps to a single canonical hostname.
- rDNS is less commonly used by end-users but critical in backend network and security processes.

---

