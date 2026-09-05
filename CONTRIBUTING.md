# Contributing

Thanks for considering a contribution. This project is a checklist, so the bar for a good change is: **does this make an AI agent's audit findings more accurate, more actionable, or more complete?**

## Ground rules

- **Keep `AUDIT-PROTOCOL.md` and `audit-protocol.html` in sync.** `AUDIT-PROTOCOL.md` is the canonical source. If you add or edit a rule there, mirror the same change in `audit-protocol.html` (both the visible section markup and the `PLAIN_TEXT` template literal in the `<script>` block used by the "Copy full prompt" button). This includes the **Search Patterns for the Agent** block — it isn't a numbered section but it's still content that must match in both files.
- **Every rule needs a severity.** Use `Critical` (direct path to data breach, account takeover, or financial loss), `High` (serious but needs another condition to be exploitable, or a serious availability/integrity risk), or `Compliance` (a legal/regulatory obligation rather than a direct exploit).
- **Every rule needs to be checkable.** Write items as things an agent (or a human) can actually go verify in code, config, or a database policy — not vague advice like "be careful with passwords." Compare to existing items for the level of specificity expected.
- **New sections need to earn their place.** Before adding a whole new numbered section, consider whether the item fits inside an existing one. The most recent sections added were Framework-Specific Traps (11) and Cost & Resource Guardrails (12) — they earned their place because middleware/Server Action auth bypass and spend-based DoS weren't well covered by items scattered across API and Infrastructure. Database Security & Data Integrity (04) was the section before that, for the same reason with RLS.
- **This stays a check protocol.** Do not add language that tells the agent to auto-fix, auto-refactor, or otherwise change code without a human-reviewed report first. If you want to propose a "fix mode" companion document, open an issue to discuss it before submitting one — it should live separately from the audit checklist so the two purposes don't get blurred.
- **Mark additions.** If you're adding to a section that traces back to the base protocol (kiliansigel.com/fix-code), mark your addition with *(added)* in `AUDIT-PROTOCOL.md` and `<span class="sec-added">added</span>` in the HTML, the same way existing additions are marked. This keeps attribution honest.

## How to propose a change

1. Open an issue describing the gap: what attack, misconfiguration, or compliance obligation isn't covered, and why it matters.
2. If you're submitting a PR directly, include:
   - The new/changed item(s) in `AUDIT-PROTOCOL.md`
   - The matching change in `audit-protocol.html` (markup + `PLAIN_TEXT`)
   - A one-line rationale in the PR description — the concrete attack or failure mode the item catches
3. Keep PRs scoped to one topic area. A PR that touches five unrelated sections is harder to review than five small PRs.

## Style

- Write rules as imperative statements ("Never trust...", "Enforce...", "Rotate...") not passive descriptions.
- Prefer naming the specific mechanism (e.g. `crypto.timingSafeEqual`, `WITH CHECK`, `169.254.169.254`) over generic advice — specificity is what makes this useful to an agent doing a real audit instead of a generic one.
- Keep each bullet to one idea. Split compound bullets.

## Reporting a mistake in an existing rule

If an existing rule is wrong, outdated, or has a better modern equivalent (e.g. a hashing algorithm recommendation that's since been superseded), open an issue or PR — security guidance changes, and this protocol should track current practice rather than what was true when a section was first written.
