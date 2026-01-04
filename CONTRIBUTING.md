# Contributing Guide

Thank you for your interest in contributing.

This project prioritizes **clarity, correctness, and auditability** over feature count.

---

## Philosophy

- Explicit is better than implicit
- Simple is better than clever
- Security > performance > convenience
- Readability is a feature

---

## What Contributions Are Welcome

✅ Accepted:
- Bug fixes
- Code clarity improvements
- Security hardening
- Documentation improvements
- Test tools (userspace helpers)
- Architecture discussions

❌ Not accepted:
- Large feature dumps without discussion
- Obfuscated or overly clever code
- Unsafe kernel practices
- Breaking the Zero-Trust model

---

## Coding Style

- Language: **C (Linux kernel style)**
- No dynamic allocation in hot paths unless justified
- No hidden side effects
- Prefer small, well-named functions
- Comments should explain **why**, not **what**

---

## Commit Guidelines

- One logical change per commit
- Clear, descriptive commit messages

Example:
