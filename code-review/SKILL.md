---
name: code-review
description: |
  Systematic code review for pull requests and changes. Use when reviewing code, giving feedback on PRs, checking security and performance, enforcing style and maintainability, or validating tests and documentation.
  Triggers: "review this code", "code review", "PR review", "review pull request", "check this change", "feedback on code".
---

# Code Review

Systematic review of code changes: security, correctness, performance, style, and maintainability.

## When to Use

- Reviewing pull requests or diffs
- Giving actionable feedback on code
- Checking for security issues, bugs, or performance regressions
- Enforcing style, naming, and structure
- Validating tests, error handling, and documentation

## Review Workflow

**Requirement:** Pull the latest `develop` (or target) and PR branches when available before computing the diff. Do not review from stale local branches.

Follow this order so high-impact issues are caught first:

1. **Pull latest branches** — Before computing the diff, pull the latest target branch (e.g. `develop`) and the PR branch in each repo from the repository mapping. Run `git fetch origin`, then update both branches if they exist (e.g. `git checkout develop && git pull`, then `git checkout <pr-branch> && git pull`). Skip or adapt if the PR branch exists only locally or the repo is not a git clone. This ensures the diff is against the current state of both branches.
2. **Scope** — Identify what changed (files, modules, dependencies). Note language, framework, and test layout.
3. **Security & correctness** — Look for injection, auth flaws, data exposure, null/edge handling, race conditions.
4. **Performance** — Expensive operations, N+1, missing indexes, unnecessary allocations, blocking calls.
5. **Design & maintainability** — SOLID, duplication, coupling, naming, file size, separation of concerns.
6. **Tests & docs** — Coverage of changed behavior, brittle tests, missing docs or comments where needed.
7. **Style & consistency** — Lint/format rules, project conventions, consistent patterns.
8. **Cleanup** — After writing the review comments file, delete the local PR branch in each repo used for the review (e.g. switch to `develop` with `git checkout develop`, then `git branch -d <pr-branch>` or `-D` if not merged). Skip if the branch was not checked out locally or the user prefers to keep it.

**Conditional focus:** If the user specifies a focus (e.g. "security only", "performance"), prioritize that area and still note critical issues in others briefly.

## Output

The **only** output of a code review is a **comments JSON file**. Write it to a single file (e.g. `pr-review-comments.json`) whose root is an **array** of thread objects. If there are any comments, include them as thread objects; if there are none, write an empty array `[]`. Do not produce a markdown report or any other output format. Full schema and examples: [references/pr-comment-format.md](references/pr-comment-format.md).

### Rules
- **Only add a comment when confident** — Skip unclear, stylistic, or low-value observations.
- **Comment content must be clear and self-contained** — Write each comment as standalone feedback the author can act on. Do **not** reference checklists, reference files (e.g. `references/checklists.md`), or any skill internals in the comment text. Use checklists and focus areas only behind the scenes to decide what to look for; the comment itself should state the issue and suggestion only.
- **One comment per thread** — Each `threadContext` is one file/range; put **exactly one** comment in that thread's `comments` array. (Publishing systems require one comment per thread.) For multiple findings at the same location, create multiple threads with the same file/range and one comment each.
- **File path** — In `threadContext.filePath`, use a path with a **leading slash** and **forward slashes** (e.g. `/Electrolux.Cache/Constants/CacheKeyConstants.cs`, `/src/Services/UserService.cs`). Do not omit the leading slash.
- **Line/offset** — `rightFileStart` and `rightFileEnd` refer to the **right (new) side** of the diff. Same line for single-line; start/end lines for a block.
- **status**: `1` = active thread. **commentType**: `1` = standard comment. **parentCommentId**: `0` for top-level comments.

### Repository Mapping
A **repository mapping** defines the source code directory for each repository. Use it to find each repo's code when reviewing PRs from multiple repositories. Before computing the diff, pull the latest target branch (e.g. `develop`) and PR branch in each mapped repo (see **Pull latest branches** in the Review Workflow). Define the mapping in a table like this:

| Repository name | Path | Notes |
|-----------------|------|-------|
| t1rearc-bff-core |  ./repos/t1rearc-bff-core | t1rearc-bff-core |

## Focus Areas

| Area | Look for |
|------|----------|
| **Security** | Injection (SQL, command, XSS), auth/authz gaps, secrets in code, unsafe deserialization, weak crypto |
| **Correctness** | Null/empty handling, error paths, boundary conditions, concurrency/races, off-by-one, wrong assumptions |
| **Performance** | O(n²) in hot paths, N+1 queries, large allocations, blocking I/O, missing caching or indexing |
| **Maintainability** | Duplication, god objects, unclear names, magic numbers, missing abstractions, tight coupling |
| **Tests** | Missing cases for new behavior, flaky or overspecified tests, no tests for critical paths |
| **Docs** | Public API without docs, misleading comments, missing README/usage for new behavior |

## Best Practices

1. **One finding per item** — Each bullet is one issue with a clear suggestion.
2. **Praise good choices** — Call out solid patterns, tests, or design so they’re reinforced.
3. **Match depth to change size** — Small PR: concise; large refactor: call out architecture and risk.
4. **Assume good intent** — Phrase as "consider…" / "suggest…" rather than accusatory.
5. **Prefer references** — Use project docs, style guides, or `references/checklists.md` **only internally** to guide your review; do not cite them in the comment content written to the JSON file.

## Reference Files

| File | Contents |
|------|----------|
| [references/checklists.md](references/checklists.md) | Detailed checklists for security, performance, and maintainability |
| [references/pr-comment-format.md](references/pr-comment-format.md) | JSON schema and examples for PR comment output |

## Quick Decision Matrix

| Review type | Prioritize |
|-------------|------------|
| Security-sensitive (auth, payments, PII) | Security → Correctness → Rest |
| Performance-critical path | Performance → Correctness → Rest |
| Refactor / structure change | Design & maintainability → Tests → Rest |
| Bug fix | Correctness → Tests → Rest |
| Feature with new API | Correctness → Docs & tests → Design → Rest |
