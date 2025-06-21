# Sender Policy Framework (SPF)

**Overview**  
SPF is an email authentication protocol that enables domain owners to publish a list of servers authorized to send email on behalf of the domain. It works by defining an SPF record in DNS (TXT record), listing allowed IPs or hostnames.

The receiving email server checks the **envelope-from** (Return-Path) address during the SMTP transaction to verify if the sending IP matches the published SPF policy. :contentReference[oaicite:1]{index=1}

---

## Operation

1. **Sender publishes SPF record** in DNS specifying authorized senders.
2. **Receiver extracts sending IP** and SMTP MAIL FROM domain.
3. **DNS lookup** retrieves the SPF record.
4. **IP comparison** performed against mechanisms like `ip4`, `a`, `mx`, `include`.
5. **Qualifier result** is determined: `pass`, `fail`, `softfail`, `neutral`.
6. **Email handling** based on the result, often marking or rejecting suspicious mail. :contentReference[oaicite:2]{index=2}

---

## SPF Record Components

- `v=spf1` – protocol version.
- Mechanisms:
  - `ip4:<addr>/<mask>`, `ip6:<addr>/<mask>`
  - `a`, `mx`, `include:<domain>`
  - `exists:<domain>`, `ptr:<domain>` (rarely used)
- Qualifiers:
  - `+` (pass), `-` (fail), `~` (softfail), `?` (neutral; default is `+`)
- Terminated with `all` qualifier (e.g., `-all`, `~all`).

---

## Strengths & Limitations

**Strengths**  
- Prevents spoofing by verifying source IP legitimacy.  
- Improves email deliverability and domain reputation. :contentReference[oaicite:3]{index=3}

**Limitations**  
- Only checks server IP, not message content.  
- Fails with forwarded emails that break source IP chains. :contentReference[oaicite:4]{index=4}

---

## Context

- Defined in **RFC 7208** (IETF, 2014). :contentReference[oaicite:5]{index=5}  
- Works best alongside DKIM and DMARC for comprehensive email authentication.
