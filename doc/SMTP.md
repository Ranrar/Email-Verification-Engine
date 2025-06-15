# Simple Mail Transfer Protocol (SMTP)

## Overview

SMTP is the core protocol used for sending and relaying email across the internet. It operates over TCP, commonly on port 25 for relay, port 587 for submission, and port 465 for SMTPS.

---

## Roles

- **Client (Sender MTA)**: Initiates the connection and sends the message.
- **Server (Receiver MTA)**: Accepts and processes the message for delivery or forwarding.

---

## Basic Workflow

1. **Handshake (EHLO/HELO)**: Establish identity and supported extensions.
2. **MAIL FROM**: Specifies the envelope sender address.
3. **RCPT TO**: Designates one or more recipients.
4. **DATA**: Begins message transfer (headers + body).
5. **QUIT**: Ends session.

---

## Common Ports

- **25**: Standard SMTP relay (between servers)
- **587**: Message submission with authentication (STARTTLS)
- **465**: SMTP over implicit TLS (SMTPS, deprecated but still used)

---

## Features

- Supports **extensions** like STARTTLS, AUTH, PIPELINING.
- Can integrate with **SPF**, **DKIM**, and **DMARC** for authentication.
- Handles delivery retries and error notifications (NDR/DSN).

---

## SMTP Response Codes

- `2xx`: Success
- `4xx`: Temporary failure (retry later)
- `5xx`: Permanent failure (bounce)

---

## Limitations

- Does not handle email retrieval (see IMAP/POP3).
- Can be exploited if misconfigured (e.g., open relay).
