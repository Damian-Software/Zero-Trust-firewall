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

---

## Research & Enterprise Context

This project is intentionally positioned between:

- academic research
- enterprise security architecture
- kernel-level systems engineering

It is **not a product**, but a **reference design**.

---

## Intended Use Cases

- Studying Zero-Trust enforcement at kernel level
- Prototyping new firewall / authorization protocols
- Teaching kernel networking and security concepts
- Evaluating SPA-like models in controlled environments

---

## Design Constraints

The following constraints are intentional:

- No userspace control plane
- No configuration DSL
- No automatic rule learning
- No silent fallbacks

These choices keep the system:
- auditable
- deterministic
- resistant to configuration drift

---

## Comparison to Traditional Firewalls

| Feature | Traditional Firewall | This Project |
|------|----------------------|-------------|
| Default policy | Allow with rules | Deny everything |
| Trust model | Network-based | Identity-based |
| Rule lifetime | Static | Time-limited |
| Control plane | Complex | Minimal |
| Auditability | Medium | High |

---

## Academic Note

The architecture aligns with modern research trends:
- Zero-Trust Networking
- Capability-based access
- Explicit authorization channels
- Kernel-enforced security boundaries

This repository may be cited or referenced in academic or internal research.

