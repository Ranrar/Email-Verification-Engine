# SPF (Sender Policy Framework) Cheat Sheet

## Qualifiers (Before Mechanisms)

| Symbol | Name     | Meaning                                                                 |
|--------|----------|-------------------------------------------------------------------------|
| `+`    | Pass     | The IP **is authorized** – allow the message                            |
| `-`    | Fail     | The IP **is not authorized** – reject the message                       |
| `~`    | SoftFail | The IP **is probably not authorized** – accept but mark as suspicious   |
| `?`    | Neutral  | **No policy** – SPF makes no assertion about this IP                    |

> The default qualifier is `+`, but most SPF records end with `~all` or `-all`.

---

## 🔧 Common SPF Mechanisms

| Mechanism   | Example                              | Description                                                               |
|-------------|--------------------------------------|---------------------------------------------------------------------------|
| `all`       | `-all`, `~all`                       | Matches everything – usually used at the end of the record                |
| `ip4`       | `ip4:192.0.2.0/24`                   | Allow this IPv4 address or subnet                                         |
| `ip6`       | `ip6:2001:db8::/32`                  | Allow this IPv6 address or subnet                                         |
| `a`         | `a`, `a:example.com`                 | Allow the IP(s) of the domain's A record                                  |
| `mx`        | `mx`, `mx:example.com`               | Allow the IP(s) of the domain’s MX servers                                |
| `include`   | `include:_spf.google.com`            | Inherit SPF rules from another domain                                     |
| `exists`    | `exists:%{i}._spf.example.com`       | Allow if the DNS query returns a result (advanced use cases)             |
| `ptr`       | `ptr:example.com`                    | Allow if the reverse DNS (PTR) matches – **not recommended**             |

---

## Examples

```txt
v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all