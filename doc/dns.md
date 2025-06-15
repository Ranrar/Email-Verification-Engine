# DNS (Domain Name System)

## Overview
The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It translates human-readable domain names (like `example.com`) into machine-readable IP addresses (like `192.0.2.1` or `2001:db8::1`).

## Key Functions

### Name Resolution
DNS resolves domain names into IP addresses so that browsers and other applications can locate and communicate with servers hosting websites, email services, or other network resources.

### Namespace Hierarchy
DNS uses a tree-like structure with different levels:
- **Root zone:** The top of the DNS hierarchy, managed by root servers.
- **Top-Level Domains (TLDs):** Examples include `.com`, `.org`, `.net`, country codes like `.dk`.
- **Second-Level Domains:** Registered domain names under TLDs.
- **Subdomains:** Further subdivisions created by domain owners.

### DNS Records
DNS servers store various types of resource records (RRs), including:
- **A (Address) Record:** Maps a domain to an IPv4 address.
- **AAAA Record:** Maps a domain to an IPv6 address.
- **CNAME (Canonical Name):** Alias of one domain to another.
- **MX (Mail Exchange):** Specifies mail server responsible for receiving email.
- **NS (Name Server):** Indicates authoritative DNS servers for a domain.
- **TXT:** Holds arbitrary text data, often for SPF, DKIM, or verification.

### DNS Query Types
- **Recursive Query:** A DNS resolver asks a DNS server to respond with the final answer, performing any necessary queries on behalf of the client.
- **Iterative Query:** The DNS server replies with the best answer it can, often a referral to another DNS server.

### DNS Caching
DNS resolvers and operating systems cache DNS responses to speed up future lookups and reduce DNS traffic.

### Importance
DNS is essential for the usability of the internet, abstracting numerical IP addresses into memorable names, allowing users to easily access websites and services.

---

