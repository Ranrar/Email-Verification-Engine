# DomainKeys Identified Mail (DKIM)

**Overview**  
DKIM uses public-key cryptography to sign outbound emails. A private key signs the message headers and body, and the corresponding public key is published in DNS under a selector. The recipient verifies the signature to prove the message is genuine and untampered. :contentReference[oaicite:6]{index=6}

---

## Operation

1. **Generate key pair** (e.g., RSA 2048-bit).
2. **Publish public key** in DNS as TXT record:  
   `selector._domainkey.example.com` with fields `v=DKIM1; k=rsa; p=<public-key>`.
3. **Signing stage**: Mail Transfer Agent (MTA) adds a `DKIM-Signature` header, covering headers and message body.
4. **Receiving stage**: MTA retrieves public key via selector and verifies signature integrity and authenticity. :contentReference[oaicite:7]{index=7}

---

## Key Fields in `DKIM-Signature`

- `v` – protocol version (DKIM1)
- `d` – signing domain
- `s` – selector
- `a` – algorithm (e.g., rsa-sha256)
- `h` – signed headers (must include `From`)
- `bh` – body hash
- `b` – signature block

Signature validation confirms both the identity and integrity of the email. :contentReference[oaicite:8]{index=8}

---

## Benefits & Considerations

**Benefits**  
- Verifies message integrity and origin.  
- Supports partial header and body signing.  
- Selector-based key management allows rotation without downtime. :contentReference[oaicite:9]{index=9}

**Considerations**  
- Broken by message modifications (e.g., forwarding or list footers).  
- Keys must be managed and rotated regularly.

---

## Context

- Defined in **RFC 6376** (2011), with updates in later RFCs. :contentReference[oaicite:10]{index=10}  
- Complements SPF by validating message content and sender identity.