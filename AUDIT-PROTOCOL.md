# AI Security & GDPR Audit Protocol

**System directive — for AI coding agents (Claude, Cursor, Copilot, Codex, Lovable, etc.)**

> **This is a CHECK protocol, not a FIX protocol.** Its job is to find and report violations of the mandates below, with evidence, severity, and the concrete attack each one enables. It does not authorize an agent to silently rewrite a production codebase. See [Execution Order](#execution-order-for-the-ai) for how findings should be reported, and how fixes — if requested — should be applied one at a time with re-verification.

## Instruction to the AI

Audit the provided codebase against every mandate below. Assume the application is already deployed and reachable by an attacker.

- Do not accept a rule as satisfied because it "looks fine" — verify it in the actual code, config, or database policy.
- Do not propose a fix that weakens or disables a protection in order to make a feature work or a test pass.
- Where closing a gap requires a product decision (e.g. "what's our data retention period", "do we require MFA for this role"), state the decision that's needed instead of guessing an answer.
- Default mode is **report only**. Do not modify code unless explicitly asked to in a follow-up step, and even then, follow the verification loop in the Execution Order section.
- ***(added)*** **Staleness note:** this protocol encodes practices believed correct as of its last edit. Before relying on anything version- or CVE-specific (a package's current safe version, a provider's current default behavior, a just-announced vulnerability), verify it against current documentation or an advisory database rather than trusting this document's memory of it.

---

## Search Patterns for the Agent *(new section)*

A checklist tells a human what to look for. An autonomous agent also needs *where* to look. Run these before relying on manual inspection alone — treat every hit as a lead to verify against the relevant rule, not as a confirmed finding.

**Secrets & key scoping**
- `rg -n "service_role"` — any hit outside a server-only file or CI secret store needs manual review against [§3](#03-api-design-secrets--concurrency) and [§11](#11-framework-specific-traps).
- `rg -n "NEXT_PUBLIC_|VITE_|REACT_APP_" | rg -i "key|secret|token|password"` — a secret-shaped name behind a client-exposed prefix is a leak by construction.
- `rg -n "process\.env\.[A-Z_]*(SECRET|KEY|TOKEN)"` in any file under a `client/`, `components/`, or `app/` directory that isn't marked server-only.
- `rg -n "\|\|\s*['\"]"` near `process.env` — flags weak fallback secrets like `JWT_SECRET || 'dev'`.

**Injection & unsafe rendering**
- `rg -n "dangerouslySetInnerHTML|v-html|innerHTML\s*="` — every hit needs a DOMPurify call in the same path or it's a [§2](#02-input-handling-injection--execution-traps) finding.
- `rg -n "\$\{.*\}.*(SELECT|INSERT|UPDATE|DELETE)" -i` and `rg -n "query\(\`"` — template-literal SQL is a concatenation injection until proven parameterized.
- `rg -n "eval\(|new Function\(|child_process|exec\("` — trace every result back to whether user input reaches it.

**Authorization gaps**
- `rg -n "\.update\(req\.body\)|\.create\(req\.body\)"` — mass-assignment candidates for [§2](#02-input-handling-injection--execution-traps).
- `rg -n "createClient\("` then check which key each call site uses and whether that route is publicly reachable.
- For every `middleware.ts`/`middleware.js` file, extract the `matcher` config and diff it against the actual route tree — routes outside the matcher get no middleware protection at all.
- `rg -n "'use server'"` — audit every Server Action found this way for auth and input validation as if it were a public API route (see [§11](#11-framework-specific-traps)).

**Storage & buckets**
- `rg -n "storage\.from\(|createBucket|PutObjectCommand|\.upload\("` — for each, check the bucket's access policy and whether the stored path is scoped to the uploading user.
- List bucket contents directly via the provider CLI/dashboard rather than trusting application code's intent — the deployed policy is the ground truth, not the code that (maybe) set it.

---

## Table of Contents

1. [Authentication, Authorization & Session Management](#01-authentication-authorization--session-management)
2. [Input Handling, Injection & Execution Traps](#02-input-handling-injection--execution-traps)
3. [API Design, Secrets & Concurrency](#03-api-design-secrets--concurrency)
4. [Database Security & Data Integrity](#04-database-security--data-integrity)
5. [Error Handling & Information Disclosure](#05-error-handling--information-disclosure)
6. [GDPR & Privacy Compliance](#06-gdpr--privacy-compliance)
7. [AI & LLM Integration Risks](#07-ai--llm-integration-risks)
8. [Infrastructure & Deployment](#08-infrastructure--deployment)
9. [Multi-Tenancy & Business Logic](#09-multi-tenancy--business-logic)
10. [Monitoring & Incident Response](#10-monitoring--incident-response)
11. [Framework-Specific Traps](#11-framework-specific-traps)
12. [Cost & Resource Guardrails](#12-cost--resource-guardrails)
13. [Execution Order for the AI](#execution-order-for-the-ai)

Severity tags: **Critical** · **High** · **Compliance**. Items marked *(added)* extend the original base protocol (see [Credits](README.md#credits)).

---

## 01. Authentication, Authorization & Session Management

### Broken Object Level Authorization (BOLA / IDOR) — Critical
- Never trust object identifiers (`id`, `uuid`, `slug`) supplied in requests, URLs, or hidden form fields.
- Scope every read and write to the authenticated principal: `WHERE id = :id AND user_id = :current_user_id`.
- On Postgres/Supabase: enable Row Level Security on every table and write explicit policies. RLS off = no authorization.
- Return `404` (not `403`) for objects the caller does not own, so IDs cannot be enumerated.

### Broken Function Level Authorization (BFLA) — Critical
- Never rely on UI state, hidden routes, or client-side role flags for access control.
- Enforce RBAC/ABAC server-side on every endpoint, including admin, cron, webhook, and internal routes.
- Store roles in a dedicated roles table, never on the user/profile row the user can update themselves.
- Deny by default: new endpoints must be unreachable until a policy explicitly allows them.

### Query Injection (SQL / NoSQL / GraphQL) — Critical
- No string concatenation or template literals in queries. Use parameter binding, prepared statements, or a query builder.
- Reject operator objects in NoSQL filters (`$gt`, `$ne`, `$where`) coming from request bodies.
- Limit GraphQL query depth, complexity, and batching to prevent abuse.

### Session, JWT & Cookie Security — High
- Prefer `HttpOnly`, `Secure`, `SameSite=Strict/Lax` cookies over `localStorage`/`sessionStorage` for session tokens.
- Verify the signature server-side on every request. Reject `alg: none`, pin the expected algorithm, enforce `exp`/`iat`/`aud`/`iss`.
- Rotate and invalidate sessions on login, logout, password change, and privilege change.
- Never put secrets or unverified claims (role, plan, credits) in a client-readable token and trust them later.
- ***(added)*** Regenerate the session ID/token immediately after successful login — a pre-auth session ID carried into a post-auth session is a **session fixation** vector.
- ***(added)*** Invalidate *every other active session* when a user changes their password, email, or MFA settings — not just issue a new token for the current device.

### Passwords, Tokens & Timing Attacks — High
- Hash passwords with Argon2id or bcrypt (cost ≥ 12). Never MD5, SHA-1, raw SHA-256, or plaintext.
- Compare secrets, API keys, admin passwords, and reset tokens with a constant-time function (`crypto.timingSafeEqual`).
- Password reset and email verification tokens: random ≥ 128 bit, single-use, short-lived, hashed at rest.
- Support MFA where accounts hold money, PII, or admin power.
- ***(added)*** Check new passwords against a breached-password list (e.g. via a k-anonymity range query against Have I Been Pwned) at signup and reset — strength rules alone don't stop credential-stuffed passwords.
- ***(added)*** Rate-limit and lock out by *account* as well as by IP for login and OTP attempts — IP-only limits are trivially bypassed with residential proxy pools.

### OAuth, SSO & Federated Login — Critical *(added)*
- Validate the `state` parameter on every OAuth callback — its absence is a CSRF hole that lets an attacker bind their own account to a victim's session.
- Validate `redirect_uri`/`return_to` against an exact allowlist, not a prefix or substring match — a loose match is an open redirect that leaks auth codes/tokens.
- Verify the token `aud` (audience) claim matches *your* client ID before trusting any claim inside it.
- Never auto-link or auto-merge accounts based on an email claim alone unless the provider confirms `email_verified` — this is a common account-takeover path via unverified-email providers.
- Store and rotate OAuth client secrets the same way as any other secret (see [§3](#03-api-design-secrets--concurrency)); never in frontend code, even "confidential" SPA flows.

### Account Recovery, Impersonation & Step-Up Auth — High *(added)*
- Require re-authentication ("step-up") immediately before changing email, password, MFA method, payout details, or deleting the account — not just an active session.
- If support/admin tooling includes a "log in as user" feature, require a distinct permission for it, log every use with who/when/why, and notify the affected user.
- Security questions, if used at all, are a fallback of last resort, never a primary recovery path — treat answers as low-entropy secrets, not public trivia.

---

## 02. Input Handling, Injection & Execution Traps

### Cross-Site Scripting (XSS) — Critical
- Do not bypass framework escaping: avoid `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, and unsanitized Markdown renderers.
- If raw HTML is unavoidable, sanitize with DOMPurify on a strict allowlist.
- Ship a Content-Security-Policy without `unsafe-inline`/`unsafe-eval`; add `X-Content-Type-Options`, `Referrer-Policy`, and HSTS.
- Validate that user-supplied URLs use `http`/`https` only — `javascript:` and `data:` URLs in `href`/`src` are XSS.

### Mass Assignment & Prototype Pollution — High
- Never pass a raw request body into a mutation (`User.update(req.body)`). Whitelist fields explicitly.
- Validate every input with a schema (Zod/Joi) — types, length, enum, format — and strip unknown keys.
- Block recursive merges of untrusted objects; reject `__proto__`, `constructor`, and `prototype` keys.

### Command Execution & Path Traversal — Critical
- Never pass user input to `exec`, `eval`, `new Function`, deserialization of untrusted data, or a shell.
- Normalize and allowlist file paths; confirm the resolved path stays inside the intended directory.
- For uploads: verify content type by magic bytes, cap size, randomize stored filenames, never serve from an executable path.

### Server-Side Request Forgery (SSRF) — High
- If the app fetches user-supplied URLs, resolve DNS first and block loopback, link-local, private ranges (10/8, 172.16/12, 192.168/16), and `169.254.169.254` (cloud metadata endpoint).
- Disable redirect following or re-validate each hop. Set timeouts and response size limits.

### ReDoS & Resource Exhaustion — High
- Avoid nested quantifiers (`(a+)+`) on untrusted input; cap input length before matching.
- Bound pagination, batch sizes, JSON body size, and file/image processing dimensions.

### CSRF — High
- Cookie-authenticated state-changing endpoints need `SameSite` plus an anti-CSRF token or origin check.
- Never allow `GET` requests to mutate state.

---

## 03. API Design, Secrets & Concurrency

### Secret Exposure — Critical
- Service-role keys, DB URLs, `STRIPE_SECRET_KEY`, LLM keys, and signing secrets must never reach the client bundle — no `VITE_`/`NEXT_PUBLIC_` prefixes, no client fetch with those keys.
- No weak fallbacks: `process.env.JWT_SECRET || 'dev'` is a production backdoor. Fail closed on missing config.
- Keep secrets out of the repo, the frontend, error responses, and logs. Rotate anything that was ever committed.

### Backend-as-a-Service Key Scoping (Supabase / Firebase / PlanetScale) — Critical *(added)*
- The anon/public key is the only key allowed in client bundles. Never initialize a client with the service-role/service-account key in code that ships to the browser or in a client-callable edge/serverless function that lacks its own auth check.
- The service-role key bypasses RLS entirely — any handler using it is a full bypass of every policy in [§4](#04-database-security--data-integrity), so treat every service-role call site as needing its own independent authorization check.
- Rotate the service-role key immediately if it was ever pasted into client code, committed, shared in a support ticket, or included in a prompt to an AI coding tool.
- Watch for naming that blurs the two keys — an env var like `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` is already a leak by construction.

### CORS & Headers — High
- Never combine `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`. Use an explicit origin allowlist.
- Restrict allowed methods and headers to what the endpoint actually needs.

### Rate Limiting & Abuse Control — High
- Rate-limit per IP *and* per account on login, signup, password reset, OTP, contact forms, payments, and any AI/LLM endpoint.
- Add exponential backoff or lockout after repeated failures, and a spend cap on metered third-party calls.
- Protect public write endpoints (waitlists, comments) with a bot check or proof-of-work.

### Race Conditions & Money — Critical
- Use transactions, row locks, or atomic updates for balances, inventory, credits, coupon redemption, and idempotent webhooks.
- Verify payment webhook signatures and process each event ID exactly once. Never trust price or amount sent from the client — read it server-side.

### API Surface & Protocol Gaps — High
- Disable GraphQL introspection and the GraphiQL/Playground UI in production — it hands attackers the full schema.
- Retire old API versions on a schedule; an unpatched v1 left live after v2 ships is a live attack surface. Apply the same auth, rate-limit, and validation rules to every version, not just the current one.
- Authenticate WebSocket connections at the handshake, not just on the first message; re-validate on reconnect.
- Apply the same rate limiting and payload validation to socket events as to REST endpoints — chat, live dashboards, and multiplayer state channels are common blind spots.

### Excessive Data Exposure & Object Property Authorization — Critical *(added)*
- Never return a raw ORM object or full DB row from an endpoint. Define an explicit response shape (DTO/serializer) that lists exactly which fields go out.
- Audit list and detail endpoints for internal fields leaking by accident: password hashes, internal flags, cost/margin data, other users' emails or phone numbers nested in related-object responses.
- A field being *authorized to view* is not the same as it being *safe to include by default* — apply the same allowlist discipline to responses as to inputs (this is the read-side mirror of mass assignment in [§2](#02-input-handling-injection--execution-traps)).

### API Key & Token Lifecycle — High *(added)*
- Issue scoped keys (least privilege, per-environment — dev keys must not work against prod). Store them hashed, not plaintext, and show the raw value only once at creation.
- Support revocation that takes effect immediately without a redeploy; expire unused or stale keys on a schedule.
- Log key usage (which key, from where, how often) so a leaked key shows up as an anomaly — see [§10 Monitoring](#10-monitoring--incident-response).

### Idempotency & Retries — High *(added)*
- Require an idempotency key on POST endpoints that create orders, charges, or side effects — a client retry after a timeout must not double-charge or double-create.
- Make webhook handlers idempotent by event ID (see Race Conditions above) even when the sender is expected to be well-behaved.

### Service-to-Service & Internal APIs — High *(added)*
- Internal network placement is not an authorization boundary. Authenticate service-to-service calls (mTLS or signed service tokens) even when both sides sit inside the same VPC.
- Internal-only endpoints (admin, cron, batch jobs) get the same auth and input validation as public ones — "nobody will guess this URL" is not a control.

### Dependencies, Build & Supply Chain — High
- Pin and audit dependencies; remove unused packages. Check for known CVEs before shipping.
- Ensure debug endpoints, seed scripts, mock auth bypasses, and admin backdoors are absent from production builds.
- Watch for dependency confusion: internal package names must be reserved or scoped, or a public package of the same name can be installed instead.
- Verify lockfile integrity in CI (`npm ci` / frozen lockfile) so a tampered or drifted lockfile fails the build instead of installing silently.
- Run SAST and dependency/CVE scanning as a CI gate, not a one-time manual pass.

---

## 04. Database Security & Data Integrity *(new section)*

### Least-Privilege Roles — Critical
- The application's runtime database user is not the superuser/owner role, and cannot run DDL. Use a separate, more privileged role for migrations only, run under CI/CD control — not by the running app.
- Different services/tenants that share a database use different credentials where the platform supports it, so one compromised service account doesn't expose everything.

### Row Level Security, Done Completely — Critical
- RLS policies exist for `SELECT`, `INSERT`, `UPDATE`, and `DELETE` separately. A `USING` clause without a matching `WITH CHECK` on `INSERT`/`UPDATE` lets an authenticated user *write* rows into another tenant's data even though they can't read them back directly.
- Every RLS policy is tested with a non-owner account, not just verified by reading the policy definition — policies that look correct can still fail against edge cases like `NULL` tenant IDs or service-role bypasses.

### Constraints as a Second Line of Defense — High
- Foreign keys, `NOT NULL`, `CHECK`, and `UNIQUE` constraints are enforced at the database level, not only in application code — an application bug should not be able to write orphaned, negative, or otherwise impossible rows.
- Money and quantity columns have `CHECK` constraints preventing negative balances/stock where negative values are never valid.

### Migrations — High
- No destructive migration (`DROP COLUMN`, `DROP TABLE`, lossy type change) runs against production without a reviewed rollback plan and a fresh backup taken immediately before.
- Migrations run through CI/CD with a distinct, audited credential — not manually against production from a developer's machine.
- Long-running migrations on large tables use batching/online-schema-change tooling so they don't hold locks that take the app down.

### Backups & Restore — Critical
- Backups are automated, encrypted at rest, and stored in a separate account/region from production.
- Restore is tested on a schedule and the result is verified against a checklist — an untested backup is not a backup.
- Backup retention matches the retention period stated in the privacy policy (see [§6](#06-gdpr--privacy-compliance)) — backups are themselves a place deleted data can keep existing.
- Backup buckets/snapshots are confirmed *not* publicly readable and are not reachable with the same credentials as the running application.

### Performance-as-Security — High
- Every column used in an RLS policy or a `WHERE user_id = ...` / `WHERE tenant_id = ...` filter is indexed. An unindexed tenant filter degrades under load into an availability problem (a form of DoS) as data grows.
- N+1 query patterns and unbounded `SELECT *` on large tables are flagged — they're a performance issue today and a resource-exhaustion vector once an attacker can trigger them repeatedly.

### Replication, Caches & Sensitive Columns — High
- Data deleted or redacted on the primary is also removed from read replicas, caches (Redis/Memcached), and search indexes within a bounded, documented time — a "deleted" record readable from a stale replica is still a data breach.
- The highest-sensitivity columns (national ID numbers, card data if ever touched, health data) use field-level encryption or tokenization in addition to disk-level encryption, so a raw DB dump doesn't expose them in the clear.
- Database connections use TLS; connection strings are never logged, checked into the repo, or included in error messages.

### Object Storage & Buckets — Critical *(added)*
- Storage buckets (Supabase Storage, S3, R2, Firebase Storage) default to public in many quick-start templates — confirm the deployed bucket policy explicitly rather than assuming it's private because the code intends it to be.
- Apply the same per-object authorization as database rows: a signed, time-limited URL or a policy scoped to the owning user — never a globally-guessable static path.
- Never accept a client-supplied storage key/path without validating it belongs to the requesting user's namespace — this is IDOR applied to files instead of rows.
- Check that database backups, exports, or debug dumps were never written into a public-facing bucket "temporarily" and left there.
- Treat bucket listing (`ListObjects`, `.list()`) as sensitive on its own: if a bucket allows public listing, an attacker enumerates every file even when individual files require a token.

### Audit Trail — Compliance
- Security-relevant tables (roles, permissions, financial ledgers, admin actions) have an append-only audit log recording who changed what and when, separate from the application's regular activity logs.

---

## 05. Error Handling & Information Disclosure

### Production Leaks — High
- Never return raw database errors, stack traces, SQL, file paths, or environment values to the client.
- Log details server-side with a correlation ID; return a generic message and a correct status code.
- Keep timing and error text identical for "user not found" and "wrong password" to prevent account enumeration.

### Sensitive Logging — High
- Redact passwords, tokens, cookies, API keys, card data, and PII from logs, error trackers, and analytics.
- Do not log full request bodies of auth or payment routes.

---

## 06. GDPR & Privacy Compliance

### Data Minimization & Storage — Compliance
- Collect only what the feature needs right now; define a retention period and delete on schedule.
- Never store unencrypted PII in `localStorage`, `sessionStorage`, URLs, or client-side state that persists.
- Encrypt PII at rest and in transit; restrict who and what service role can read it.

### Consent & Third Parties — Compliance
- Load analytics, tracking pixels, external fonts, maps, and CDNs only after explicit opt-in consent — or self-host them.
- No pre-ticked boxes, no cookie wall that hides a "reject all" option of equal prominence.
- Truncate or hash IP addresses before storing them for rate limiting or analytics.
- List every processor (hosting, email, payments, AI provider) in the privacy policy, including transfers outside the EU.

### Data Subject Rights — Compliance
- Implement real hard deletion across all tables, queues, caches, backup policy, and third-party systems — not just a `deleted_at` flag.
- Provide an authenticated export endpoint returning the user's data as JSON or CSV.
- Log consent (what, when, version) and support withdrawal that is as easy as giving it.
- Every marketing email needs a working one-click unsubscribe that suppresses future sends.

### Additional Obligations — Compliance
- Detect and document breaches; regulators and, where required, affected users must be notified within 72 hours of becoming aware.
- Support rectification — a user correcting inaccurate data about themselves — not only export and deletion.
- If the product could plausibly be used by anyone under the local age of digital consent, gate signup with age verification and parental consent handling.
- Have a signed Data Processing Agreement with every third-party processor named in the privacy policy — listing them is not sufficient on its own.

---

## 07. AI & LLM Integration Risks

### Prompt Injection — Critical
- Treat all user input, retrieved documents, web pages, and tool output as untrusted data, never as instructions.
- Separate system instructions from data with clear delimiters and re-state constraints after user content.
- Assume the model can be talked into anything: enforce authorization in code, not in the prompt.

### Unsafe Model Output — High
- HTML-encode or sanitize model output before rendering; never `eval` it or execute generated SQL/shell directly.
- Validate structured output against a schema before it touches the database.

### Excessive Agency — High
- Give agents the narrowest possible tool scopes and read-only access by default.
- Require human confirmation for deletions, payments, emails to real users, and permission changes.
- Never expose the model's provider key to the browser; proxy through your own rate-limited backend endpoint.

### Data Leakage — Critical
- Do not send secrets, other users' records, or full PII into third-party model APIs. Redact before sending.
- Disclose AI processing and the provider in the privacy policy.

---

## 08. Infrastructure & Deployment

### Environments & Exposure — Critical
- Staging, preview, and demo environments (Lovable/Vercel/Netlify preview URLs) must not hold production data, and need the same auth as prod — "preview" is not a security boundary.
- Admin panels and internal tools live behind a distinct auth layer and, where possible, an IP allowlist — never just a hard-to-guess path.

### TLS & Transport — High
- Enforce HTTPS everywhere with an HTTP→HTTPS redirect; enable HSTS (with preload once verified stable).
- Confirm certificates on every custom domain are valid and auto-renewing, not self-signed or expired.

### Exposed Surface — High
- Confirm `.env`, `.git`, seed/config files, and build artifacts are not served publicly; check `robots.txt` and `sitemap.xml` don't map internal-only routes.
- Audit DNS: a dangling CNAME pointing at a deprovisioned Netlify/Heroku/S3 target is a takeover waiting to happen.

---

## 09. Multi-Tenancy & Business Logic

### Isolation Beyond the Database — Critical
- Tenant isolation must hold in shared caches, queues, search indexes, and background jobs, not only in Postgres RLS — a job runner that loops over "all users" can leak across tenants even with RLS on.

### Logic Can Be Attacked, Not Just Inputs — High
- Check for workflow-skipping: calling a later-stage endpoint (e.g. "confirm order") without the required prior step (e.g. "pay") actually happening.
- Check for abuse of coupons, referrals, and credits: stacking, reuse, negative quantities, or claiming a referral bonus without a real referred action.

### Client-Side Gates Are Not Gates — High
- Any paywall or premium feature must be enforced server-side; a flag that only hides a button in the UI is not access control.

---

## 10. Monitoring & Incident Response

### Detection — High
- Alert on anomalous auth activity: repeated failed logins, impossible-travel logins, sudden role/permission changes.
- Monitor spend and usage on metered third-party APIs (LLM calls, SMS, email) for anomalies that indicate a leaked key.

### Response — High
- Keep a written runbook for what happens when a secret leaks: which keys rotate, who's notified, what gets revoked, in what order.
- Restrict who can read logs and error-tracker data — logs holding correlation IDs, IPs, and request metadata are themselves sensitive.

---

## 11. Framework-Specific Traps *(new section)*

### Next.js Middleware & Route Auth — Critical
- Middleware-based auth checks run at the edge and can be bypassed by requests hitting the underlying route handler directly if the handler doesn't also check auth itself — treat middleware as a first line, never the only line.
- Extract the `matcher` config from every middleware file and diff it against the real route tree; a narrowly-scoped matcher silently leaves new routes unprotected as the app grows.

### Server Components, Server Actions & the Client/Server Boundary — Critical
- A Server Action is a public HTTP endpoint the moment it's exported — apply the same auth, input validation, and rate limiting as any API route, not "it's only called from a trusted page."
- Never pass a full object (user, order, record) from a Server Component into a Client Component as a prop without stripping server-only fields first — anything serialized to the client is visible in the page payload regardless of whether it's rendered.
- Confirm modules marked `server-only`, or that import secrets or a DB client, are never imported — even transitively — by a file that ships to the client bundle. A shared "utils" file imported by both sides is a common leak vector.

### Static Generation, ISR & Personalized Data — High
- Never let a statically generated or revalidated (ISR) page embed one user's data — check every cached route for accidental cross-user data bleed, since a cache serves the same bytes to the next visitor.

---

## 12. Cost & Resource Guardrails *(new section)*

### Serverless & Function Spend — High
- Set a concurrency limit or budget alert on serverless functions (Vercel, Netlify, Lambda, Supabase Edge Functions) — an unbounded function reachable from a public endpoint is a billing-DoS vector, not only an availability one.
- Confirm recursive or self-triggering chains (a write that fires a webhook that triggers the same function again) can't loop unbounded.

### Database & Storage Spend — High
- Cap query result size and row-scan limits on any endpoint driven by user input — an unindexed query with attacker-controlled filters is both a performance and a cost problem on usage-billed databases.
- Set storage bucket size and egress alerts; an unauthenticated upload endpoint (see [§2](#02-input-handling-injection--execution-traps)) is a storage-cost vector as well as a security one.

### Third-Party Metered APIs — High
- Confirm the spend cap on metered third-party calls required in [§3](#03-api-design-secrets--concurrency) actually exists in the provider dashboard, not only as a TODO — a missing cap on an AI, SMS, or email API is the most common source of an unexpected bill in a vibe-coded app.

---

## Execution Order for the AI

This protocol is a **checklist for finding problems**, not a license to rewrite the codebase unattended. Follow this order:

1. **Search.** Run the search patterns above (secrets, unsafe rendering, authorization gaps, storage) to build a candidate list of files and call sites before manual review.
2. **Scan.** Go through the codebase against every mandate above, across backend functions, database policies, config, infrastructure, and client code.
3. **Evidence.** For each finding, cite the exact file/line, config key, or database policy involved. State the concrete attack it enables in one sentence — not just which rule it breaks.
4. **Rank.** Order findings by exploitability × blast radius. A critical bug in a rarely-used internal tool may rank below a high-severity bug on the public signup flow.
5. **Report.** Return a bulleted findings report grouped by section number, including severity, evidence, and the attack. **Do not modify any code in this pass.** Flag anything that needs a human product decision instead of guessing.
6. **Fix (only if explicitly requested).** Address findings one at a time. After each fix, re-verify it against the *same* rule before moving to the next — and never satisfy a rule by disabling or weakening the check that caught it.
7. **Re-verify.** Once fixes are applied: re-check auth on each touched endpoint, confirm RLS is on and complete (all four operations) for every touched table, confirm no secret is reachable from the client bundle, confirm tenant isolation holds outside the database, and confirm no service-role key or bucket policy was reopened by the fix.

---

*This checklist is a technical aid, not legal advice. Compliance obligations depend on your jurisdiction, your data, and your processors — have a lawyer review your privacy policy and data processing agreements.*

*Base protocol: [kiliansigel.com/fix-code](https://kiliansigel.com/fix-code). See [README → Credits](README.md#credits) for the full attribution and list of extensions in this fork.*
