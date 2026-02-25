# PR Comment Output Format

JSON schema for posting review comments to specific lines or blocks. Use when the user requests PR comments or inline feedback.

---

## Root structure

The output is a **JSON array**. Each element is a **thread** (one location in one file). **Each thread must contain exactly one comment.** Systems that publish these comments (e.g. Azure DevOps) require each comment to be attached to its own thread; multiple comments in one thread will fail to publish. If you have two separate findings on the same line, create two threads with the same `threadContext` and one comment each.

```json
[
  { "comments": [{ ... }], "status": 1, "threadContext": { ... } },
  { "comments": [{ ... }], "status": 1, "threadContext": { ... } }
]
```

---

## Thread object

| Field | Type | Description |
|-------|------|-------------|
| `comments` | array | **Exactly one** comment object for this location. Do not add multiple comments in one thread. |
| `status` | number | Thread status; use `1` for active |
| `threadContext` | object | File path and line range (right side of diff) |

---

## Comment object (inside `comments`)

| Field | Type | Description |
|-------|------|-------------|
| `parentCommentId` | number | `0` for top-level comments in the thread |
| `content` | string | The review comment text: clear, self-contained feedback. Do not reference checklists or skill references; use those only behind the scenes. Markdown allowed if supported. |
| `commentType` | number | Comment type; use `1` for standard comment |

---

## threadContext object

| Field | Type | Description |
|-------|------|-------------|
| `filePath` | string | Path to the file: **must start with `/`** and use **forward slashes** (e.g. `/Electrolux.Cache/Constants/CacheKeyConstants.cs`, `/src/Services/UserService.cs`). |
| `rightFileStart` | object | Start of the range on the **new** side of the diff |
| `rightFileEnd` | object | End of the range on the **new** side of the diff |

### rightFileStart / rightFileEnd

| Field | Type | Description |
|-------|------|-------------|
| `line` | number | 1-based line number |
| `offset` | number | 1-based column offset (use `1` if not targeting a column) |

- **Single line:** set `rightFileStart` and `rightFileEnd` to the same `{ line: N, offset: 1 }`.
- **Block (multiple lines):** set `rightFileStart` to the first line and `rightFileEnd` to the last line.

---

## Full example

One comment per thread. Single-line, block, and multiple files in one array:

```json
[
  {
    "comments": [
      {
        "parentCommentId": 0,
        "content": "Consider using a parameterized query here to avoid SQL injection.",
        "commentType": 1
      }
    ],
    "status": 1,
    "threadContext": {
      "filePath": "/src/Services/UserService.cs",
      "rightFileStart": { "line": 45, "offset": 1 },
      "rightFileEnd": { "line": 45, "offset": 1 }
    }
  },
  {
    "comments": [
      {
        "parentCommentId": 0,
        "content": "This block could throw if `response` is null. Add a null check or use null-conditional before accessing `.Content`.",
        "commentType": 1
      }
    ],
    "status": 1,
    "threadContext": {
      "filePath": "/src/Services/AuthService.cs",
      "rightFileStart": { "line": 45, "offset": 1 },
      "rightFileEnd": { "line": 50, "offset": 1 }
    }
  }
]
```
---

## Confidence rule

Only include a thread when you are **confident** the finding is valid and actionable. Do not add comments for:

- Uncertain or speculative issues
- Purely stylistic nits
- Already-correct code
- Duplicate or overlapping feedback

**Comment content:** Write clear, standalone feedback. Do not reference checklists, reference files, or skill internals in the comment text — those are for internal use only.
