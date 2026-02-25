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

| Variable | Description |
|----------|-------------|
| `PR_COMMENT_CREDENTIALS_PATH` | Full path to the credentials JSON file. Default: `~/.pr-comment-mcp/credentials.json` |

Credentials are stored in a JSON file with restrictive permissions (0o600). **Do not commit this file or place it under version control.**

## Cursor MCP configuration

Add the server to Cursor (Settings → MCP, or `.cursor/mcp.json` in the project):

**Option A — uv (recommended):**

```json
{
  "mcpServers": {
    "pr-comment": {
      "command": "uv",
      "args": ["run", "fastmcp", "run", "server.py"],
      "cwd": "C:/path/to/BESkills/mcp/code_reviewer",
      "env": {}
    }
  }
}
```

**Option B — system Python** (install deps first with `uv sync` or `pip install -e .`):

```json
{
  "mcpServers": {
    "pr-comment": {
      "command": "python",
      "args": ["-m", "fastmcp", "run", "C:/path/to/BESkills/mcp/code_reviewer/server.py"],
      "cwd": "C:/path/to/BESkills/mcp/code_reviewer",
      "env": {}
    }
  }
}
```

Adjust `cwd` and paths to your machine. To override the credentials file:

```json
"env": {
  "PR_COMMENT_CREDENTIALS_PATH": "C:/path/to/my-credentials.json"
}
```

## Tools

### pr_comment_add_token

Store a PAT/token for a provider and organization (and optional project for Azure DevOps).

- **provider**: `azure_devops` (supported), `github`, `aws` (stubs).
- **org**: Organization name (e.g. Azure DevOps org).
- **token**: Personal access token or secret to store.
- **project**: Optional. For Azure DevOps, project name or ID (can use one org-level PAT and omit project, or store per-project).

### pr_comment_post

Post comment threads to a pull request.

- **provider**: `azure_devops` (required for now).
- **org**: Organization name.
- **project**: Project name (Azure DevOps).
- **repository**: Repository name or GUID.
- **pull_request_id**: PR number (integer).
- **comments_body**: JSON string — array of thread objects. Each thread must have exactly one comment, `status: 1`, and `threadContext` with `filePath` (leading `/`), `rightFileStart`, `rightFileEnd`. See [pr-comment-format.md](../../code-review/references/pr-comment-format.md).

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

Create a [Personal Access Token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens) with scope **Code (Read & Write)** or **Pull Request Threads (Read & Write)**. Use `pr_comment_add_token` to store it for the desired org (and optionally project).
