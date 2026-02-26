# PR Comment MCP Server (code_reviewer)

Post pull request review comments from an MCP client (e.g. Cursor) to Azure DevOps (and later GitHub, AWS CodeCommit). Comment body format follows [pr-comment-format.md](../../code-review/references/pr-comment-format.md).

## Setup

From the repo root or from this folder:

```bash
cd mcp/code_reviewer
uv sync
```

This creates a virtual environment and installs dependencies from `pyproject.toml`. To use the system Python instead, run `uv sync --no-install-project` or install with pip: `uv pip install -e .`

## Running the server

**Development / test:**

```bash
cd mcp/code_reviewer
uv run fastmcp dev server.py
```

**Production (e.g. Cursor MCP):**

```bash
cd mcp/code_reviewer
uv run fastmcp run server.py
```

Or run the module directly:

```bash
cd mcp/code_reviewer
uv run python -m fastmcp run server.py
```

**Deploy with uvicorn (HTTP):**

```bash
cd mcp/code_reviewer
uv run python run.py
```

Or with uvicorn explicitly (custom host/port/reload):

```bash
cd mcp/code_reviewer
uv run uvicorn run:app --host 0.0.0.0 --port 8000
uv run uvicorn run:app --host 0.0.0.0 --port 8000 --reload   # development
```

## Environment

The server **does not store tokens**. Tokens are keyed by **provider, org, and project**.

**Key format:** `{provider}_{org}_{project}_token` — e.g. `azure_devops_electrolux_T1_token`.

| Source | Format |
|--------|--------|
| **SSE/HTTP** | Header **`X-{provider}-{org}-{project}-token`** (e.g. `X-azure-devops-electrolux-T1-token: <PAT>`). Underscores in provider/org/project become dashes in the header. Multiple keys = multiple headers. |
| **SSE/HTTP (alt)** | Header `X-PR-Comment-Tokens` with a JSON object: `{"azure_devops_electrolux_T1_token": "<PAT>", ...}`. |
| **stdio** | One env var per key: `PR_COMMENT_<KEY_UPPERCASED>` — e.g. `PR_COMMENT_AZURE_DEVOPS_ELECTROLUX_T1_TOKEN=<PAT>`. |
| **Fallback** | Single token: header `Authorization: Bearer <PAT>` or `X-PR-Comment-Token`, or env `PR_COMMENT_TOKEN`. Used when the keyed lookup is missing. |
| **Tool param** | Optional `token` argument on `post_pr_comments` / `approve_pr` overrides lookup for that call. |

No X-User-Id or user identity is required.

## Cursor MCP configuration

Add the server to Cursor (Settings → MCP, or `.cursor/mcp.json` in the project).

**Option A — SSE (recommended for Cursor):** Run the server manually with SSE, then point Cursor at the URL.

1. Start the server:
   ```bash
   uv run python server.py --transport sse --host 127.0.0.1 --port 8080
   ```
2. In `mcp.json`, pass tokens via the keyed header (or use fallback for a single token):
   ```json
   {
     "mcpServers": {
       "code-review": {
         "url": "http://127.0.0.1:8080/sse",
         "headers": {
           "X-azure-devops-electrolux-T1-token": "YOUR_AZURE_DEVOPS_PAT"
         }
       }
     }
   }
   ```
   **Alternative (multiple keys):** `"X-PR-Comment-Tokens": "{\"azure_devops_electrolux_T1_token\": \"YOUR_PAT\"}"`. **Fallback (single token):** `"Authorization": "Bearer YOUR_PAT"` or `"X-PR-Comment-Token": "YOUR_PAT"`.

**Option B — stdio with uv:**

Set the token via the keyed env var (or fallback `PR_COMMENT_TOKEN` for a single provider/org/project):

```json
{
  "mcpServers": {
    "code-review": {
      "command": "uv",
      "args": ["run", "fastmcp", "run", "server.py"],
      "cwd": "C:/path/to/BESkills/mcp/code_reviewer",
      "env": {
        "PR_COMMENT_AZURE_DEVOPS_ELECTROLUX_T1_TOKEN": "YOUR_AZURE_DEVOPS_PAT"
      }
    }
  }
}
```

Fallback: use `PR_COMMENT_TOKEN` for a single token. Do not commit PATs; use a secret manager or local-only env.

**Option C — stdio with system Python** (install deps first with `uv sync` or `pip install -e .`):

```json
{
  "mcpServers": {
    "code-review": {
      "command": "python",
      "args": ["-m", "fastmcp", "run", "C:/path/to/BESkills/mcp/code_reviewer/server.py"],
      "cwd": "C:/path/to/BESkills/mcp/code_reviewer",
      "env": {
        "PR_COMMENT_AZURE_DEVOPS_ELECTROLUX_T1_TOKEN": "YOUR_AZURE_DEVOPS_PAT"
      }
    }
  }
}
```

Adjust `cwd` and paths to your machine.

## Tools

### post_pr_comments

Post comment threads to a pull request. Token is resolved by key `{provider}_{org}_{project}_token` from header **`X-{provider}-{org}-{project}-token`** (e.g. `X-azure-devops-electrolux-T1-token`) or `X-PR-Comment-Tokens` (JSON), or env `PR_COMMENT_<KEY_UPPERCASED>`; fallback: `Authorization: Bearer` / `X-PR-Comment-Token` / `PR_COMMENT_TOKEN`; or pass optional `token` parameter.

- **provider**: `azure_devops` (required for now).
- **org**: Organization name.
- **project**: Project name (Azure DevOps).
- **repository**: Repository name or GUID.
- **pull_request_id**: PR number (integer).
- **comments_body**: JSON string — array of thread objects. Each thread must have exactly one comment, `status: 1`, and `threadContext` with `filePath` (leading `/`), `rightFileStart`, `rightFileEnd`. See [pr-comment-format.md](../../code-review/references/pr-comment-format.md).
- **token** (optional): PAT for this call. Omit to use keyed header/env or fallback.

Example `comments_body`:

```json
[
  {
    "comments": [{ "parentCommentId": 0, "content": "Consider using a parameterized query here.", "commentType": 1 }],
    "status": 1,
    "threadContext": {
      "filePath": "/src/Services/UserService.cs",
      "rightFileStart": { "line": 45, "offset": 1 },
      "rightFileEnd": { "line": 45, "offset": 1 }
    }
  }
]
```

## Azure DevOps PAT

Create a [Personal Access Token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens) with scope **Code (Read & Write)** or **Pull Request Threads (Read & Write)**. Pass it via header **`X-azure-devops-<org>-<project>-token`** or `X-PR-Comment-Tokens` (JSON), or env `PR_COMMENT_AZURE_DEVOPS_<ORG>_<PROJECT>_TOKEN=<PAT>`. Fallback: `Authorization: Bearer <PAT>`, `X-PR-Comment-Token`, or `PR_COMMENT_TOKEN`. The server does not store tokens.
