# BESkills

Skills and MCP tools for backend development and code review.

---

## Code Review Skill — Setup

Use the **code-review** skill to review pull requests and post comments via the PR Comment MCP. Follow these steps once per machine (or per project).

### 1. Add PR Review MCP to Cursor (SSE)

Add the PR Comment MCP server so you can store tokens and post review comments to Azure DevOps (or GitHub/AWS later). Use **SSE** (Server-Sent Events) so Cursor connects to the server via a URL.

**1.1. Start the MCP server with SSE** (in a terminal, or run as a background service):

```bash
cd mcp/code_reviewer
uv sync
uv run python server.py --transport sse --host 127.0.0.1 --port 8080
```

Keep this process running while using Cursor. Default port is `8080`; change `--port` if needed.

**1.2. Add the server to Cursor**

- **Option A — Project config:** Create or edit `BESkills/.cursor/mcp.json` (commit to repo to share with the team).
- **Option B — User config:** Cursor Settings → Tools & MCP → Add new MCP server (uses your user config, e.g. `~/.cursor/mcp.json`).

Add an entry for the PR Comment MCP with the SSE URL. Example:

```json
{
  "mcpServers": {
    "pr-comment": {
      "url": "http://127.0.0.1:8080/sse",
      "headers": {
        "X-User-Id": "you@company.com"
      }
    }
  }
}
```

- Use the same host and port as in the `server.py` command (e.g. if you use `--port 3000`, set `"url": "http://127.0.0.1:3000/sse"`).
- **User identity required:** Set `X-User-Id` (SSE/HTTP) in the config above, or set `USER_ID` in the server’s `env` for stdio. The server will error if neither is set when you call add_token or post_pr_comments.
- Optional: add a token for auth: `"url": "http://127.0.0.1:8080/sse?token=YOUR_TOKEN"` (if your server validates it).

Restart Cursor after changing MCP config so it connects to the SSE endpoint.

### 2. Store your PR token

Before running reviews, store your Personal Access Token so the MCP can post comments. In Cursor, use one of these prompts:

- **"Store PR token for Azure DevOps. Org: \<your-org\>, Project: \<your-project\>, Token: \<paste PAT\>."**
- Or: **"Use the add_token tool to store an Azure DevOps PAT for org \<org\> and project \<project\>. Token: \<PAT\>."**

You must pass a user identity when storing the token (or have `X-User-Id` / `USER_ID` set as in step 1).

### 3. Copy the code-review skill to Cursor skills folder

Copy the `code-review` folder into your Cursor skills directory so Cursor can load the skill:

| OS      | Destination |
|---------|-------------|
| Windows | `%USERPROFILE%\.cursor\skills\code-review\` |
| macOS / Linux | `~/.cursor/skills/code-review/` |

**From the BESkills repo root:**

```powershell
# Windows (PowerShell)
New-Item -ItemType Directory -Force "$env:USERPROFILE\.cursor\skills"
Copy-Item -Recurse -Force ".\code-review" "$env:USERPROFILE\.cursor\skills\code-review"
```

```bash
# macOS / Linux
mkdir -p ~/.cursor/skills
cp -R ./code-review ~/.cursor/skills/code-review
```

Ensure the folder contains `SKILL.md` and the `references/` subfolder (e.g. `checklists.md`, `pr-comment-format.md`).

### 4. Create `repos` folder and clone projects

Create a `repos` directory (e.g. next to the BESkills repo or inside it) and clone every repository that may be reviewed:

```powershell
# Windows (PowerShell) — example: repos beside BESkills
cd C:\Users\<you>\Desktop\workspace\khanhct
mkdir -Force repos
cd repos
git clone <clone-url-for-repo-1>
git clone <clone-url-for-repo-2>
# ... repeat for each project
```

```bash
# macOS / Linux
mkdir -p repos && cd repos
git clone <clone-url-for-repo-1>
git clone <clone-url-for-repo-2>
```

### 5. Update repository mapping in SKILL.md

Edit the **Repository Mapping** table in the skill’s `SKILL.md`. Use the **copied** skill file under `.cursor\skills\code-review\SKILL.md` (or the one in this repo if you prefer to edit here and re-copy).

Set each repository’s path to the local clone under `repos`:

| Repository name | Path | Notes |
|-----------------|------|-------|
| my-org/repo-a   | `./repos/repo-a` | Or full path, e.g. `C:/Users/you/workspace/repos/repo-a` |
| my-org/repo-b   | `./repos/repo-b` | |

Paths are relative to the workspace root where you run the review, or use absolute paths so they work from any CWD.

---

## Code Review — Prompts

After setup (including storing your PR token in step 2), use these prompts in Cursor.

### Review a pull request

Run a full code review and (optionally) post comments to the PR:

- **Prompt:**  
  **"Using the code review skill, review \<PR link\>."**

Example:

- **"Using the code review skill, review https://dev.azure.com/my-org/my-project/_git/repo-a/pullrequest/123."**

The agent will:

1. Use the code-review skill (workflow, evaluation criteria, checklists).
2. Pull latest target and PR branches, compute the diff, and review changed files.
3. Produce a comments JSON file (e.g. `pr-review-comments.json`).
4. If the PR Comment MCP is enabled and a token is stored, you can ask to post those comments to the PR (see **Post PR comments** below).

For **Azure DevOps**, the PR link usually contains org, project, repo, and pull request ID; the agent can infer them or you can specify: “Post these comments to Azure DevOps org X, project Y, repository Z, PR 123.”

### Post PR comments

After a review has produced a comments file, post its contents to the PR using the MCP:

- **Prompt:**  
  **"Post PR comments from @pr-review-comments.json"**

- Or:  
  **"Let’s post PR comments. Use @pr-review-comments.json and post them to this PR."**

You may need to specify provider, org, project, repository, and pull request ID if the agent cannot infer them from context (e.g. from a PR link or the current branch).

---

## Repo structure

- **`code-review/`** — Code review skill (`SKILL.md` + `references/`). Copy to `.cursor/skills/code-review/`.
- **`mcp/code_reviewer/`** — MCP server that stores PATs and posts PR comment threads. See `mcp/code_reviewer/README.md` for tools and Azure DevOps PAT scope.
