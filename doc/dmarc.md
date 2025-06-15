# Domain-based Message Authentication, Reporting & Conformance (DMARC)

**Overview**  
DMARC builds on SPF and DKIM to verify alignment between the domain in the `From:` header and the authenticated domain. It also specifies handling instructions (none, quarantine, reject) and allows for aggregate and forensic reporting. :contentReference[oaicite:11]{index=11}

---

## Operation

1. **Publish DMARC record** in DNS: `_dmarc.example.com TXT "v=DMARC1; p=policy; rua=...; ruf=...; pct=...; adkim=...; aspf=..."`
2. **Receive email** and perform SPF and DKIM validation.
3. **Check alignment**:
   - SPF alignment: `MAIL FROM` domain vs. `From:` header
   - DKIM alignment: `d=` tag domain vs. `From:` header
4. **Enforce policy** (none/quarantine/reject) if neither aligns/passes.
5. **Generate reports** per `rua`, `ruf` for domain owner insight.

---

## Key Tags

- `v=DMARC1` – protocol version
- `p=` – policy: `none`, `quarantine`, `reject`
- `rua=` – aggregate report addresses
- `ruf=` – forensic report addresses
- `pct=` – apply policy to a %, default 100
- `adkim=` – DKIM alignment: `s` (strict) or `r` (relaxed)
- `aspf=` – SPF alignment: `s` or `r`

---

## Purpose and Benefits

- Protects against spoofing/phishing by enforcing alignment. :contentReference[oaicite:12]{index=12}  
- Enables visibility through reports on authentication outcomes.  
- Helps domain owners improve email infrastructure and maintain brand trust.

---

## Context

- Defined in **RFC 7489** (2015). :contentReference[oaicite:13]{index=13}  
- Builds on SPF and DKIM, adding policy enforcement and reporting.

---

## Scope & Limitations

DMARC only verifies direct path spoofing—does not prevent look-alike domains or display-name abuse. It relies on underlying SPF/DKIM infrastructure and proper alignment to function. :contentReference[oaicite:14]{index=14}
