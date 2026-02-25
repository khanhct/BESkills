# Code Review Checklists

Detailed checklists for security, performance, and maintainability. Use when performing a deep or focused review.

---

## Security Checklist

- [ ] **Injection** — All user/input data parameterized or sanitized (SQL, NoSQL, command, LDAP, XSS). No string concatenation for queries or shell commands.
- [ ] **Authentication** — No bypass paths; session/token validation on every protected route; secure password hashing (e.g. Argon2id, bcrypt).
- [ ] **Authorization** — Resource-level checks; no reliance on client for permissions; 403/401 on backend.
- [ ] **Secrets** — No keys, passwords, or tokens in code, logs, or comments; use env/config/secrets manager.
- [ ] **Data exposure** — No PII/sensitive data in logs, errors, or responses; appropriate masking or redaction.
- [ ] **Deserialization** — Safe parsers; no unserialize of untrusted input; validate schema/size.
- [ ] **Crypto** — Approved algorithms and key sizes; no custom crypto; secure randomness for tokens/IVs.
- [ ] **Dependencies** — Known vulnerable packages (e.g. OWASP Dependency-Check); versions pinned.

---

## Performance Checklist

- [ ] **Algorithms** — No unnecessary O(n²) or worse in hot paths; appropriate data structures.
- [ ] **Queries** — No N+1; batch or join where needed; pagination for large result sets.
- [ ] **Indexes** — DB queries use indexes; no full scans on large tables without justification.
- [ ] **Allocations** — No large or frequent allocations in loops; reuse buffers/objects where possible.
- [ ] **I/O** — No blocking calls on async paths; timeouts and limits on external calls.
- [ ] **Caching** — Consider caching for repeated expensive work; cache invalidation strategy.
- [ ] **Concurrency** — No unnecessary locking; correct use of async/parallel; no deadlocks.

---

## Maintainability Checklist

- [ ] **Duplication** — Shared logic extracted; DRY without over-abstracting.
- [ ] **Naming** — Clear, consistent names; no single-letter except trivial loop vars.
- [ ] **Size** — Functions/classes within reasonable size; single responsibility.
- [ ] **Coupling** — Dependencies minimal and explicit; no hidden globals or side effects.
- [ ] **Magic values** — Constants or config for literals; no unexplained numbers/strings.
- [ ] **Error handling** — Errors handled or propagated; no swallowed exceptions; meaningful messages.
- [ ] **Public API** — Clear contracts; documented parameters and return values; backward compatibility considered.

---

## Test & Doc Checklist

- [ ] **Coverage** — New behavior has tests; critical paths and edge cases covered.
- [ ] **Quality** — Tests are deterministic; no flaky timing or order dependence; meaningful assertions.
- [ ] **Docs** — Public APIs documented; README or usage updated if behavior or setup changed.
- [ ] **Comments** — Complex logic explained; comments accurate and not redundant with code.

---

Use these as reference during review; cite the checklist item (e.g. "Security: parameterize query") when raising a finding.
