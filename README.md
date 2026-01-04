# Zero-Trust Firewall (Linux Kernel Module)

A **Linux kernel firewall** implementing a **Zero-Trust network access model** using Netfilter hooks.

All traffic to a protected service port is **denied by default** and is only allowed after an explicit **authorization packet** is received. Authorization creates a **time-limited allow rule** bound to the source IP and protocol.

This project is a **reference implementation** intended for:
- kernel developers
- security engineers
- Zero-Trust / SPA research
- learning Netfilter and kernel networking

---

## Features

- Linux **kernel-space** firewall
- **Default deny** policy
- SPA-like authorization channel
- Time-limited access (TTL)
- No userspace daemon required
- Minimal and auditable C code
- Realtime logging via `dmesg`

---

## Architecture Overview

**Incoming packet**
--> **Netfilter PRE_ROUTING**
-->**AUTH packet (AUTH_PORT)** ?
-->* verify** -->**allow flow (TTL)**
--> **PROTECTED_PORT** ?
--> **allow only if authorized**

---

## Requirements

- Linux server with loadable modules
- Kernel headers matching the running kernel
- `gcc`, `make`
- Root privileges

---

### Install Dependencies
---
### Debian / Ubuntu

```bash
    sudo apt update
    sudo apt install -y build-essential linux-headers-$(uname -r)
```
---
Alternative (not recommended for module build):
```bash
bash
sudo apt install -y linux-libc-dev
```
---
### Fedora
```bash
sudo dnf install -y gcc make kernel-headers kernel-devel
```
---
### Arch Linux
```bash
sudo pacman -S --needed base-devel linux-headers
```
---
### Build
`make`

### Result:
`main.ko`

### Clean:
`make clean`
---
### Load Module
```bash
sudo insmod main.ko AUTH_PORT=40000 PROTECTED_PORT=9000 ALLOW_TTL_SEC=30
```
---
###Unload:
    sudo rmmod main
	
---
### Module Parameters
| Parameter        | Description                             | Example |
| ---------------- | --------------------------------------- | ------- |
| `AUTH_PORT`      | UDP port used for authorization packets | `40000` |
| `PROTECTED_PORT` | Protected destination port              | `9000`  |
| `ALLOW_TTL_SEC`  | Authorization lifetime (seconds)        | `30`    |
---
### Testing
**Watch logs**
```bash
sudo dmesg -w
```
### Test without authorization (should DROP)
```bash
echo test | nc -u -w1 <SERVER_IP> 9000
```

### Send authorization packet
```bash
echo AUTH | nc -u -w1 <SERVER_IP> 40000
```

### Expected log:
```bash
AUTH OK allow <IP> -> port 9000
```

### Test again (should ALLOW)
```bash
echo test | nc -u -w1 <SERVER_IP> 9000
```
### TTL expiration
**After ALLOW_TTL_SEC seconds, traffic is blocked again automatically.**

**Security Notes**
⚠️ The authorization mechanism is intentionally simple and NOT cryptographically secure.

- Before any real deployment:
- replace demo auth with HMAC or signatures
- add replay protection
- rate-limit AUTH_PORT
- audit thoroughly

**See SECURITY.md for details.**

