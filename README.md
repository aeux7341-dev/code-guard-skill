# High-Risk Code Guard (`high-risk-code-guard`)

An AI Agent Skill designed to enforce strict **security**, **financial safety**, **privacy protection**, and **zero-regression guardrails** whenever an AI coding assistant writes, refactors, or audits production code.

---

## Key Protection Pillars

1. **Zero-Regression Guard:** Prevents AI from silently deleting existing edge-case validations, changing function signatures, or breaking existing features during code refactoring.
2. **Security & Anti-Exploit:** Blocks SQL/Command Injection, XSS, CSRF, IDOR (Broken Object-Level Authorization), and hardcoded credentials/API keys.
3. **Financial & Resource Safety:** Enforces integer/decimal arithmetic for money (no IEEE 754 `float` drift), atomic database transactions with `SELECT ... FOR UPDATE` row locking, idempotency keys, webhook signature verification, and hard cost/rate circuit breakers for paid APIs.
4. **Privacy & Data Protection:** Prevents sensitive PII, password hashes, session tokens, and internal stack traces from leaking via API responses or application logs.

---

## Repository Structure

```text
high-risk-code-guard/
├── SKILL.md                        # Core AI Agent skill definition & workflow rules
├── README.md                       # Repository documentation & installation guide
├── LICENSE                         # MIT License
├── scripts/
│   └── audit_scanner.py            # Automated static scanner for secrets, SQLi, XSS, & float math
├── references/
│   └── secure-patterns.md          # Vulnerable vs. hardened code patterns (Node.js, PHP, SQL, TS)
└── examples/
    └── atomic-payment.ts           # Constant-time webhook verification & integer currency template