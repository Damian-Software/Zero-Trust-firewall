# Zero-Trust Firewall (Linux Kernel)

A minimalistic **Zero-Trust firewall implemented as a Linux kernel module**, designed as a **clean reference architecture** rather than a production-ready appliance.

The firewall follows a **default-deny** model and dynamically allows traffic **only after explicit cryptographic authorization (SPA-like handshake)**.

This project is intended for:
- kernel developers
- security engineers
- researchers
- anyone designing custom firewall / Zero-Trust protocols at kernel level

---

## ✨ Key Features

- Linux **kernel-space firewall** (Netfilter hook)
- **Zero-Trust by design** (no open ports by default)
- **Single Packet Authorization (SPA)** style access
- Dynamic, time-limited flow allowlist
- Stateless auth + stateful enforcement
- Realtime kernel logging
- Minimal, readable, extensible C code
- No userspace dependencies

---

## 🧠 Architecture Overview

**Traffic flow:**

