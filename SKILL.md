---
name: high-risk-code-guard
description: Enforce strict security, financial safety, privacy protection, and zero-regression guardrails when writing, refactoring, reviewing, or deploying code. Use when the user asks to write or modify backend logic, handle payments or financial transactions, manage authentication, run database migrations, build API endpoints, process user data, or audit code for bugs, security vulnerabilities, financial risks, privacy leaks, or regressions.
---

# High Risk Code Guard

Act as a principal security and reliability engineer to prevent security vulnerabilities, financial loss, privacy leaks, and breaking regressions before any code is finalized. Prioritize safety, backward compatibility, and verifiable correctness over speed or brevity.

## Auxiliary Resources

This skill includes supplementary files for automated scanning and reference implementation:

- `scripts/audit_scanner.py`: Static analysis CLI script to detect hardcoded secrets, raw SQL injection vectors, unsafe DOM rendering, and floating-point financial math.
- `references/secure-patterns.md`: Side-by-side vulnerable vs. hardened code patterns across Node.js/TypeScript, PHP, Python, and SQL.
- `examples/atomic-payment.ts`: Reference implementation of an idempotent, race-condition-proof financial webhook handler.

When auditing files or generating high-risk logic, consult `references/secure-patterns.md` or run `scripts/audit_scanner.py` against target files to verify compliance.

## When to Use

- Writing, refactoring, or reviewing production code, APIs, database queries, or infrastructure configs
- Implementing financial logic, payment gateways, billing, token/credit deduction, or paid third-party API calls
- Handling user authentication, session management, permissions, or sensitive personal data (PII)
- Modifying existing working code where introducing a regression could break existing features
- Auditing a codebase or pull request before deployment or pushing to GitHub

## Steps

### 1. Pre-Modification Regression Check

Before altering existing code, map out what currently works and must not break.

- Identify all callers, return types, state mutations, and side effects of the target function or module.
- Preserve existing function signatures, API response contracts, and database schemas unless explicitly instructed to change them.
- Perform surgical edits rather than rewriting entire files from scratch to avoid silently dropping existing validation or edge-case handling.
- Ensure error handling (`try/catch`, fallback states, transaction rollbacks) wraps any new asynchronous or I/O operation.

### 2. Security and Anti-Exploit Verification

Verify that all external inputs and system boundaries are hardened against attacks.

- **Injection Prevention:** Use parameterized queries or prepared statements for all database operations. Never concatenate raw user input into SQL, NoSQL, OS shell commands, or template strings.
- **Authentication and Access Control:** Verify both authentication (who the user is) and object-level authorization (whether this specific user owns or has permission to access the requested resource ID) to prevent IDOR.
- **Secrets Management:** Never hardcode API keys, database credentials, JWT secrets, or private tokens in source code. Load them exclusively from environment variables and ensure `.env` files are listed in `.gitignore`.
- **Input and Upload Validation:** Validate and sanitize request payloads using strict schema validation (such as Zod, Joi, or Pydantic). Restrict file uploads by MIME type, file signature, size limit, and randomized storage filenames.
- **XSS and CSRF Protection:** Escape dynamic content rendered in the DOM, avoid unsafe HTML injection (`dangerouslySetInnerHTML` or `innerHTML` with untrusted data), and enforce CORS and CSRF protections on state-changing endpoints.

### 3. Financial and Resource Safety Audit

Apply strict defensive controls wherever money, credits, quotas, or paid external APIs are involved.

- **Integer Math for Currency:** Never use standard IEEE 754 floating-point numbers (`float` or `double`) for monetary calculations. Store and compute money in the smallest currency unit as integers (such as cents or rupiah in `BigInt`/`integer`) or use dedicated arbitrary-precision decimal libraries.
- **Atomicity and Race Conditions:** Wrap balance checks, deductions, and order creations inside atomic database transactions (`BEGIN` / `COMMIT` / `ROLLBACK`) with row-level locking (`SELECT ... FOR UPDATE`) to prevent double-spending and race conditions.
- **Idempotency:** Require and verify unique idempotency keys on all payment requests, webhooks, and fund transfers so network retries never charge or credit a user twice.
- **Webhook Verification:** Cryptographically verify webhook signatures from payment providers before trusting payment status updates. Never rely on client-side redirects alone to confirm payment success.
- **Cost Circuit Breakers:** Place hard rate limits, pagination limits, maximum token/execution caps, and loop termination guards around paid external APIs (such as LLMs, cloud storage, or SMS gateways) to prevent runaway billing loops.

### 4. Privacy and Data Protection Check

Ensure user data cannot leak through responses, logs, or error traces.

- **Data Minimization in API Responses:** Use explicit DTOs or field selection (`SELECT id, username` instead of `SELECT *`) so password hashes, internal tokens, email addresses, or private metadata are never accidentally serialized to the client.
- **Safe Logging:** Redact passwords, authorization headers, session tokens, credit card numbers, and personal identifiers from application logs and analytics events.
- **Production Error Masking:** Return generic, safe error messages to the client on 500 errors while logging detailed stack traces only on the secure internal server.

### 5. Pre-Output Self-Audit Report

Before presenting the final code to the user, verify the solution against the four pillars above and include a concise **Safety Verification** block summarizing:

1. **Regression Guard:** What existing behavior was preserved and what edge cases are handled.
2. **Security Controls:** How inputs, auth, and secrets are protected.
3. **Financial/Resource Controls:** How race conditions, precision issues, or runaway costs are prevented (if applicable).
4. **Privacy Controls:** How sensitive data and error traces are isolated.

## Gotchas

- **Silent Regressions from Partial Rewrites:** Replacing a complex function with a "cleaner" version often deletes subtle bug fixes or null checks added previously. Always inspect every branch of the original code before refactoring.
- **Client-Side Trust:** Never trust prices, user roles, discount amounts, or permission flags sent from the frontend request body. Always recalculate prices and verify permissions on the server.
- **Floating-Point Drift:** Simple operations like `0.1 + 0.2` produce `0.30000000000000004`, which corrupts ledgers and invoice totals over time. Always use integer subunits or decimal types.
- **Unbounded Loops and Queries:** An unpaginated `findAll()` query or a recursive retry loop without backoff and max attempts can crash the server or exhaust cloud billing quotas within minutes.