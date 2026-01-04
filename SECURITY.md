# Security Policy

## Supported Versions

This project is a **kernel-level firewall reference implementation**.

Only the **latest commit on the default branch** is considered relevant.
Older commits are **not supported**.

| Version | Supported |
|--------|-----------|
| `main` | ✅ Yes |
| others | ❌ No |

---

## Security Model

This project follows a **Zero-Trust security model**:

- All traffic is denied by default
- Explicit authorization is required before allowing traffic
- Authorization is time-limited
- No implicit trust is assumed

The code is intentionally **minimal and auditable**.

---

## Cryptography Notice

⚠️ **Important**

The current implementation uses a **demo authentication mechanism** for clarity.

- It is **NOT cryptographically secure**
- It is provided only as a structural placeholder

### Before production use, you MUST:
- Replace demo authentication with:
  - HMAC-SHA256 (Linux kernel crypto API), or
  - Strong asymmetric signatures
- Add replay protection
- Add rate limiting on authorization packets
- Perform a full security audit

---

## Reporting a Vulnerability

If you discover a security issue:

1. **Do NOT open a public GitHub issue**
2. Contact the maintainer privately
3. Provide:
   - A clear description of the issue
   - Affected kernel versions
   - Proof-of-concept (if available)

Responsible disclosure is expected.

---

## Threat Model (High-Level)

This project does **NOT** aim to protect against:
- Physical access attacks
- Malicious kernel modules
- Compromised kernel / root user
- Side-channel attacks

It **does** aim to demonstrate:
- Correct Zero-Trust enforcement
- Kernel-level authorization gating
- Minimal attack surface design
