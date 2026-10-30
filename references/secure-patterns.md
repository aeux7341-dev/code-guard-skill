# Secure & Anti-Regression Code Patterns

Reference patterns comparing vulnerable implementations against hardened, production-grade patterns across Node.js/TypeScript, PHP, Python, and SQL.

## 1. Financial Transactions & Anti-Race Condition (SQL + Backend)

### Vulnerable Pattern (Race Condition & Floating-Point Drift)

```javascript
// BAD: Uses floating point, no database transaction, no row lock (vulnerable to double-spend)
app.post("/api/transfer", async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const user = await db.query(`SELECT balance FROM wallets WHERE user_id = ${req.user.id}`);
  if (user.balance >= amount) {
    await db.query(`UPDATE wallets SET balance = balance - ${amount} WHERE user_id = ${req.user.id}`);
    await db.query(`UPDATE wallets SET balance = balance + ${amount} WHERE user_id = ${req.body.toUserId}`);
    return res.json({ success: true });
  }
  res.status(400).json({ error: "Insufficient balance" });
});


Hardened Pattern (Integer Subunits, Atomic Transaction, Row Locking, Idempotency)
// GOOD: Integer validation, parameterized queries, row locking (FOR UPDATE), and idempotency key
app.post("/api/transfer", async (req, res) => {
  const senderId = req.user.id;
  const recipientId = Number.parseInt(req.body.toUserId, 10);
  const amountMinorUnits = Number.parseInt(req.body.amount, 10); // e.g., whole Rupiah or cents
  const idempotencyKey = req.headers["idempotency-key"];

  if (!idempotencyKey || !Number.isSafeInteger(amountMinorUnits) || amountMinorUnits <= 0) {
    return res.status(400).json({ error: "Invalid transfer parameters" });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Check idempotency key inside transaction
    const [existing] = await conn.execute(
      "SELECT status FROM transfer_ledgers WHERE idempotency_key = ? LIMIT 1",
      [idempotencyKey]
    );
    if (existing.length > 0) {
      await conn.rollback();
      return res.status(200).json({ status: existing[0].status, idempotentReplay: true });
    }

    // 2. Lock wallet rows in deterministic order (lowest ID first) to prevent deadlocks
    const firstLockId = Math.min(senderId, recipientId);
    const secondLockId = Math.max(senderId, recipientId);
    await conn.execute("SELECT user_id FROM wallets WHERE user_id IN (?, ?) FOR UPDATE", [
      firstLockId,
      secondLockId,
    ]);

    // 3. Verify sender balance
    const [senderRows] = await conn.execute(
      "SELECT balance_minor FROM wallets WHERE user_id = ?",
      [senderId]
    );
    if (!senderRows.length || BigInt(senderRows[0].balance_minor) < BigInt(amountMinorUnits)) {
      await conn.rollback();
      return res.status(422).json({ error: "Insufficient balance" });
    }

    // 4. Perform atomic debit, credit, and ledger insertion
    await conn.execute(
      "UPDATE wallets SET balance_minor = balance_minor - ? WHERE user_id = ?",
      [amountMinorUnits, senderId]
    );
    await conn.execute(
      "UPDATE wallets SET balance_minor = balance_minor + ? WHERE user_id = ?",
      [amountMinorUnits, recipientId]
    );
    await conn.execute(
      "INSERT INTO transfer_ledgers (idempotency_key, sender_id, recipient_id, amount_minor, status) VALUES (?, ?, ?, ?, 'COMPLETED')",
      [idempotencyKey, senderId, recipientId, amountMinorUnits]
    );

    await conn.commit();
    return res.status(200).json({ status: "COMPLETED" });
  } catch (err) {
    await conn.rollback();
    console.error("Transfer error [redacted context]:", err.message);
    return res.status(500).json({ error: "Transaction failed safely" });
  } finally {
    conn.release();
  }
});


Database Queries & IDOR Prevention (PHP PDO)
Vulnerable Pattern (SQL Injection & Broken Object-Level Authorization)
// BAD: Direct variable interpolation and no ownership check (any user can view any invoice)
$invoiceId =$_GET['id'];
$stmt =$pdo->query("SELECT * FROM invoices WHERE id = $invoiceId");
$invoice =$stmt->fetch();
echo json_encode($invoice); // Leaks internal columns


Hardened Pattern (Prepared Statement, Ownership Enforcement, Explicit Columns)
// GOOD: Prepared statement, ownership scope (user_id), and explicit field projection
$invoiceId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$invoiceId) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid invoice ID']));
}

$stmt = $pdo->prepare( 'SELECT id, invoice_number, total_minor, status, created_at FROM invoices WHERE id = :id AND user_id = :user_id LIMIT 1' );$stmt->execute([
    ':id' => $invoiceId,
    ':user_id' => $_SESSION['authenticated_user_id'],
]);

$invoice =$stmt->fetch(PDO::FETCH_ASSOC);
if (!$invoice) {
    http_response_code(404);
    exit(json_encode(['error' => 'Invoice not found']));
}

header('Content-Type: application/json');
echo json_encode($invoice);


Paid External API Circuit Breaker & Timeout Guard
// GOOD: Enforces request timeout, bounded retries, and hard token/cost ceiling
export async function callPaidApiSafely(prompt: string, userQuotaRemaining: number) {
  const MAX_PROMPT_CHARS = 4000;
  if (userQuotaRemaining <= 0) {
    throw new Error("Quota exhausted: blocking paid API call.");
  }
  if (prompt.length > MAX_PROMPT_CHARS) {
    throw new Error("Input exceeds maximum allowed length.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000); // Hard 10s timeout

  try {
    const response = await fetch("[https://api.example.com/v1/generate](https://api.example.com/v1/generate)", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAID_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        prompt,
        max_tokens: 512, // Hard cap to prevent runaway billing
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Upstream API returned status ${response.status}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

**4. File `examples/atomic-payment.ts` (Contoh Verifikasi Webhook Anti-Timing Attack)**

```typescript
/**
 * Reference Implementation: Atomic & Idempotent Payment Webhook Handler
 * Demonstrates signature verification, integer currency math, row locking,
 * and zero-leak error handling.
 */

import crypto from "crypto";

export interface WebhookPayload {
  eventId: string;
  orderId: string;
  paidAmountMinor: number; // Stored in smallest currency unit (e.g. Rupiah / Cents)
  currency: "IDR" | "USD";
}

export function verifyWebhookSignature(
  rawBody: Buffer,
  signatureHeader: string,
  secret: string
): boolean {
  if (!signatureHeader || !secret) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  const sigBuffer = Buffer.from(signatureHeader, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");

  if (sigBuffer.length !== expectedBuffer.length) {
    return false;
  }

  // Constant-time comparison prevents timing attacks
  return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
}
```

**5. File `README.md` (Dokumentasi Repositori GitHub)**

````markdown
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
```

---

## Installation & Usage

### 1. Using with AI Coding Agents (Antigravity / Gemini / Claude / Cursor)

Clone this repository into your agent's skills directory:

```bash
git clone [https://github.com/your-username/high-risk-code-guard.git](https://github.com/your-username/high-risk-code-guard.git)
```

Or copy `SKILL.md`, `scripts/`, `references/`, and `examples/` into your workspace skill folder (e.g., `.agents/skills/high-risk-code-guard/` or `~/.gemini/skills/high-risk-code-guard/`).

### 2. Running the Static Security & Financial Scanner Locally

You can run the bundled Python scanner manually or in CI/CD pipelines (GitHub Actions / Git pre-commit hook) without external dependencies:

```bash
python3 scripts/audit_scanner.py ./src
```

Example output when a risk is detected:

```text
[CRITICAL] SEC-001 | src/config/payment.js:14
  Reason : Potential hardcoded secret, API key, or private token
  Snippet: const apiKey = "sk_live_98a7s9d8f7a9s8df79a8sdf";

[HIGH] FIN-001 | src/controllers/wallet.js:42
  Reason : Floating-point parseFloat/float used on financial variable (price/amount/balance)
  Snippet: const amount = parseFloat(req.body.amount);

FAILED: Detected 2 potential high-risk issue(s).
```

---

## License

Released under the [MIT License](./LICENSE).