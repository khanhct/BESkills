# Code Review Checklists

Detailed checklists aligned with the skill’s Evaluation Criteria. Use internally to guide what to look for; do not cite this file in review comment text.

---

## Design & Architecture

- [ ] **Patterns** — Change fits existing architectural patterns and module boundaries.
- [ ] **Coupling** — No unnecessary coupling or speculative features.
- [ ] **Separation of concerns** — Clear boundaries; responsibilities not mixed across layers.
- [ ] **Module boundaries** — Changes stay within defined modules; no cross-cutting violations.

---

## Complexity & Maintainability

- [ ] **Control flow** — Remains flat; avoid deep nesting.
- [ ] **Cyclomatic complexity** — Stays low; no overly branching logic.
- [ ] **DRY** — Duplicate logic abstracted into shared helpers or modules.
- [ ] **Dead code** — No unreachable or obsolete code left in.
- [ ] **Dense logic** — Complex logic refactored into testable helper methods.

---

## Functionality & Correctness

- [ ] **Valid inputs** — New code paths behave correctly for expected inputs.
- [ ] **Invalid inputs** — Error paths and validation for bad or unexpected input.
- [ ] **Edge cases** — Boundaries, empty collections, nulls, and limits covered.
- [ ] **Idempotency** — Retry-safe operations remain idempotent where required.
- [ ] **Requirements** — Functional requirements or user stories satisfied.
- [ ] **Error handling** — Robust semantics; errors propagated or handled clearly.

---

## Readability & Naming

- [ ] **Identifiers** — Names clearly convey intent; no cryptic abbreviations.
- [ ] **Comments** — Explain *why*, not *what*; no redundant commentary.
- [ ] **Ordering** — Code blocks in logical order; related code grouped.
- [ ] **Side effects** — No surprising side effects behind simple-looking names.

---

## Best Practices & Patterns

- [ ] **Idioms** — Language- and framework-specific idioms used correctly.
- [ ] **SOLID** — Principles respected; single responsibility, clear dependencies.
- [ ] **Resource cleanup** — Handles, connections, and streams closed or disposed.
- [ ] **Logging/tracing** — Consistent approach across changed code.
- [ ] **Layers** — Clear separation of responsibilities (e.g. API, service, data).

---

## Test Coverage & Quality

- [ ] **Success paths** — Unit tests for happy path and main scenarios.
- [ ] **Failure paths** — Unit tests for errors, validation, and edge cases.
- [ ] **Integration** — End-to-end or integration tests where appropriate.
- [ ] **Mocks/stubs** — Used appropriately; no over-mocking or brittle setup.
- [ ] **Assertions** — Meaningful assertions, including edge-case inputs.
- [ ] **Test names** — Accurately describe the behavior under test.

---

## Standardization & Style

- [ ] **Style guide** — Indentation, import order, naming conventions followed.
- [ ] **Project structure** — Folder and file placement consistent with repo.
- [ ] **Linter/formatter** — No new warnings; existing rules satisfied.

---

## Documentation & Comments

- [ ] **Public API** — Parameters, return values, and contracts documented.
- [ ] **Complex algorithms** — In-code explanation where logic is non-obvious.
- [ ] **README / usage** — Updated if behavior or setup changed.
- [ ] **Swagger/OpenAPI** — API docs updated for new or changed endpoints.
- [ ] **CHANGELOG** — User-visible or config changes reflected where applicable.

---

## Security & Compliance

- [ ] **Injection** — Input parameterized or sanitized (SQL, NoSQL, command, LDAP, XSS); no string concatenation for queries or shell.
- [ ] **Output encoding** — Output encoded appropriately for context (e.g. HTML, JSON).
- [ ] **Error handling** — Errors don’t leak sensitive data or stack traces to clients.
- [ ] **Dependencies** — No known vulnerable packages; versions pinned; license checks if required.
- [ ] **Secrets** — No keys, passwords, or tokens in code/logs; use env/config/secrets manager.
- [ ] **AuthN/AuthZ** — Authentication and authorization enforced on protected resources.
- [ ] **Compliance** — Relevant regulations considered (e.g. GDPR, HIPAA) where applicable.

---

## Performance & Scalability

- [ ] **N+1** — No N+1 query patterns; batch or join where needed.
- [ ] **I/O** — Streaming vs buffering appropriate; no unnecessary full loads.
- [ ] **Memory** — No large or frequent allocations in hot paths; reuse where possible.
- [ ] **Hot path** — No heavy computation or blocking calls on critical paths.
- [ ] **UI** — No unnecessary re-renders or heavy work on main thread (if UI code).
- [ ] **Optimization** — Caching, batching, memoization, or async considered where beneficial.

---

## Observability & Logging

- [ ] **Metrics** — Key business or technical events emit metrics where applicable.
- [ ] **Tracing** — Spans or correlation IDs for distributed or important flows.
- [ ] **Log levels** — Appropriate use of debug, info, warn, error.
- [ ] **Sensitive data** — PII and secrets redacted or excluded from logs.
- [ ] **Context** — Logs include enough context for monitoring, alerting, and debugging.

---

## Accessibility & Internationalization (UI)

- [ ] **Semantic HTML** — Correct elements (headings, lists, landmarks) used.
- [ ] **ARIA** — ARIA attributes used where needed for screen readers.
- [ ] **Keyboard** — All interactive elements reachable and operable via keyboard.
- [ ] **Color contrast** — Meets contrast requirements; not relying on color alone.
- [ ] **i18n** — User-facing strings externalized for localization; no hard-coded copy.

---

Use these checklists to decide what to look for during review. Write comment text as standalone feedback; do not reference this file or checklist names in the comments.
