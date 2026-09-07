# AI Security & GDPR Audit Protocol

A checklist you paste into an AI coding agent (Claude, Cursor, Copilot, Codex, Lovable, etc.) so it audits your app's authentication, database, API, and privacy posture against a consistent, opinionated set of rules — instead of whatever the model happens to remember about security that day.

**This is a check protocol, not a fix protocol.** It's designed to make an agent *find and report* violations with evidence and severity. Turning findings into code changes is a deliberate, separate step — see [Execution Order](AUDIT-PROTOCOL.md#execution-order-for-the-ai) in the protocol itself.

## Why this exists

Code shipped through fast, AI-assisted prototyping routinely ships with vulnerabilities and legal exposure nobody explicitly decided to accept — broken object-level authorization, secrets baked into the client bundle, RLS policies that cover reads but not writes, and so on. This protocol closes those gaps by giving an agent an explicit, exhaustive list of what "done" means for security, instead of relying on it to remember everything unprompted.

## What's in this repo

| File | Purpose |
|---|---|
| [`AUDIT-PROTOCOL.md`](AUDIT-PROTOCOL.md) | The canonical, versioned source of the protocol. Read this, edit this, diff this. |
| [`audit-protocol.html`](audit-protocol.html) | A styled, single-page version of the same content with a "copy full prompt" button — open it locally or host it, and copy the plain-text prompt straight into an agent chat. |
| [`LICENSE`](LICENSE) | MIT. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to propose changes or new sections. |

Both `AUDIT-PROTOCOL.md` and `audit-protocol.html` carry the same 12 sections plus a search-patterns block for the agent; keep them in sync when editing (see CONTRIBUTING).

## How to use it

1. Open `audit-protocol.html` in a browser (or view it as a static page if you host this repo with GitHub Pages) and click **Copy full prompt** — or just copy the contents of `AUDIT-PROTOCOL.md`.
2. Paste it into your coding agent, pointed at your actual codebase.
3. Ask for a **findings report first**. The protocol already tells the agent to default to report-only mode, but say it again in your own prompt if you want to be sure: *"Report findings only, don't change any code yet."*
4. Review the findings yourself. Some will need a product decision (e.g. "what's our data retention window") that no agent should make for you.
5. Once you've reviewed the report, ask the agent to fix issues one at a time, re-verifying each fix against the same rule before moving to the next (this is spelled out in the protocol's execution order).

## What it covers

Before the numbered sections, the protocol includes a **Search Patterns for the Agent** block — concrete `rg`/grep patterns for secrets, unsafe rendering, authorization gaps, storage misconfiguration, and RLS ownership issues (e.g. `ENABLE ROW LEVEL SECURITY` without a matching `FORCE ROW LEVEL SECURITY`) — so an autonomous agent has somewhere to start instead of relying entirely on its own judgment to find the relevant code.

1. Authentication, Authorization & Session Management — BOLA/IDOR, BFLA, JWT/cookie/session hygiene, OAuth/SSO pitfalls, account-recovery abuse
2. Input Handling, Injection & Execution Traps — XSS, mass assignment, command injection/path traversal, SSRF, ReDoS, CSRF
3. API Design, Secrets & Concurrency — secret exposure, backend-as-a-service key scoping (Supabase/Firebase service-role vs anon key), CORS, rate limiting, race conditions, API versioning/WebSockets, excessive data exposure, key lifecycle, idempotency, service-to-service auth, supply chain
4. Database Security & Data Integrity — least-privilege roles (including explicit separation of the app's runtime role from the table *owner* role so RLS is never silently bypassed), complete RLS with `FORCE ROW LEVEL SECURITY` on every protected table, DB-level constraints, migration safety, backups/restore, indexing as a security concern, replication/cache consistency, object storage & bucket exposure, audit trails
5. Error Handling & Information Disclosure
6. GDPR & Privacy Compliance — data minimization, consent, data subject rights, breach notification
7. AI & LLM Integration Risks — prompt injection, unsafe model output, excessive agency, data leakage to third-party model APIs
8. Infrastructure & Deployment — environment isolation, TLS, exposed surface, DNS takeovers
9. Multi-Tenancy & Business Logic — isolation beyond the database, workflow/coupon abuse, server-side gating
10. Monitoring & Incident Response — detection, runbooks, log access control
11. Framework-Specific Traps — Next.js middleware bypass, Server Action auth, client/server boundary leaks, ISR/static-cache data bleed
12. Cost & Resource Guardrails — serverless spend, database/storage spend, third-party metered API caps

Full detail lives in [`AUDIT-PROTOCOL.md`](AUDIT-PROTOCOL.md).

## Limitations

- **This is a checklist, not a guarantee.** Passing every item reduces obvious risk; it doesn't certify the app as secure or compliant.
- **It's not legal advice.** The GDPR section tells you what to check for, not how to interpret the law for your specific business. Have a lawyer review your privacy policy and data processing agreements.
- **It's opinionated and not exhaustive.** It leans toward common web-app/SaaS patterns (Postgres/Supabase-style RLS, JWT auth, Node/Python-ish stacks). Mobile-specific, native-desktop-specific, or highly regulated-industry-specific risks (HIPAA, PCI-DSS scope, etc.) aren't covered in depth — treat this as a strong baseline, not the full picture for those contexts.
- **§11 (Framework-Specific Traps) is Next.js/React-centric.** If your stack is Django, Rails, Laravel, or something else, the underlying concerns (middleware-only auth, server/client boundary leaks, cache-embedded personalization) still apply — translate them to your framework's equivalents rather than expecting a literal match.
- **The search patterns assume `ripgrep` (`rg`) and a Unix-like shell.** Substitute `grep -rn` or your editor's project-wide search if `rg` isn't available; the patterns themselves are the useful part, not the specific tool.
- **Agent output still needs a human.** Even in "report" mode, verify findings against the actual code — LLMs can misjudge severity or miss context only you have.

## Credits

The base protocol (sections on Auth, Input Handling, Secrets/API/Concurrency, Error Handling, GDPR, and AI/LLM risks) originates from [Kilian Sigel's fix-code checklist](https://kiliansigel.com/fix-code).

This fork extends it with:
- A dedicated **Database Security & Data Integrity** section (new), including object storage & bucket exposure
- **RLS ownership & enforcement** checks (added): cross-referencing `GRANT`/`OWNER TO` statements against the runtime connection role, requiring `FORCE ROW LEVEL SECURITY` on every RLS-protected table, and flagging app roles that are also table owners (a common silent RLS bypass)
- Deeper **Authentication** coverage: OAuth/SSO pitfalls, session fixation, account-recovery/impersonation abuse, breached-password checks
- Deeper **API** coverage: excessive data exposure, API key lifecycle, idempotency, service-to-service auth, backend-as-a-service key scoping (Supabase/Firebase service-role vs. anon key)
- **Infrastructure & Deployment**, **Multi-Tenancy & Business Logic**, and **Monitoring & Incident Response** sections
- **Framework-Specific Traps** (new) — Next.js middleware bypass, Server Action auth, client/server boundary leaks
- **Cost & Resource Guardrails** (new) — serverless, database, and third-party API spend
- A **Search Patterns for the Agent** block giving an autonomous agent concrete places to start looking, not just a list of what to check
- A staleness note in the instruction block, since security guidance ages
- A rewritten "Instruction to the AI" and execution order that makes this explicitly a *check, report, then optionally fix* workflow rather than an unattended auto-refactor pass

## License

MIT — see [`LICENSE`](LICENSE). Attribution to the base protocol is appreciated but not required by the license; it's included above because it's simply true.
