# BESkills

Skills and MCP tools for backend development and code review.

---

## Code Review Skill — Setup

Use the **code-review** skill to review pull requests and post comments via the PR Comment MCP. Follow these steps once per machine (or per project).

### 1. Add PR Review MCP to Cursor (SSE)

Add the PR Comment MCP server so you can post review comments to Azure DevOps. Use **SSE** so Cursor connects via a URL. The server uses **header-only auth**: pass your PAT and (for approve/reject) reviewer ID in `mcp.json`; it does not store tokens.

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

Add an entry with the SSE URL and **keyed headers** for your Azure DevOps PAT (and reviewer ID if you use approve_pr/reject_pr):

```json
{
  "mcpServers": {
    "code-review": {
      "url": "http://127.0.0.1:8080/sse",
      "headers": {
        "X-azure-<org>-<project>-token": "YOUR_AZURE_DEVOPS_PAT",
        "X-azure-<org>-<project>-reviewer-id": "YOUR_REVIEWER_ID_GUID"
      }
    }
  }
}
```

- Replace `<org>` and `<project>` with your Azure DevOps org and project (same spelling as in the PR URL; underscores become dashes in the header). Example: org `electrolux`, project `T1` → `X-azure-electrolux-T1-token` and `X-azure-electrolux-T1-reviewer-id`.
- Use the same host/port as in the `server.py` command (e.g. `--port 3000` → `"url": "http://127.0.0.1:3000/sse"`).
- **Token** is required for `post_pr_comments` and `create_pr`. **Reviewer ID** is required for `approve_pr` and `reject_pr`. If a required header is missing, the tool returns an error.

Restart Cursor after changing MCP config so it connects to the SSE endpoint.

### 2. (Optional) Copy the code-review skill to Cursor skills folder

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

Ensure the folder contains `SKILL.md`, the `references/` subfolder, and `prompts/` (e.g. `review-and-post-pr.md`).

### 3. Create `repos` folder and clone projects

**Requirement:** Install [Git](https://git-scm.com/) and use the **git** command for cloning and all other git actions (fetch, pull, checkout, diff, etc.). The code-review workflow relies on git being available in your environment.

Create a `repos` directory (e.g. next to the BESkills repo or inside it) and clone every repository that may be reviewed using `git clone`:

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

Ensure `git` is on your PATH (`git --version` should work in a terminal). The agent and the code-review skill use git to pull branches, compute diffs, and perform branch cleanup.

### 4. Update repository mapping in SKILL.md

Edit the **Repository Mapping** table in the skill’s `SKILL.md`. Use the **copied** skill file under `.cursor\skills\code-review\SKILL.md` (or the one in this repo if you prefer to edit here and re-copy).

Set each repository’s path to the local clone under `repos`:

| Repository name | Path | Notes |
|-----------------|------|-------|
| my-org/repo-a   | `./repos/repo-a` | Or full path, e.g. `C:/Users/you/workspace/repos/repo-a` |
| my-org/repo-b   | `./repos/repo-b` | |

Paths are relative to the workspace root where you run the review, or use absolute paths so they work from any CWD.

---

## Code Review — Prompts

After setup (token and optional reviewer ID in `mcp.json` from step 1), use these prompts in Cursor.

### Review a pull request

Run a full code review and (optionally) post comments to the PR:

- **Prompt:**  
  **"Using the code review skill, review \<PR link\>."**

Example:

- **"Using the code review skill, review https://dev.azure.com/my-org/my-project/_git/repo-a/pullrequest/123."**

The agent will:

1. Use the code-review skill (workflow, evaluation criteria, checklists).
2. Pull latest target and PR branches, compute the diff, and review changed files.
3. Produce a comments JSON file named `{pr_id}.json` (e.g. `123.json` for PR 123).
4. If the PR Comment MCP is enabled and the token header is set in `mcp.json`, you can ask to post those comments to the PR (see **Post PR comments** below).

For **Azure DevOps**, the PR link usually contains org, project, repo, and pull request ID; the agent can infer them or you can specify: “Post these comments to Azure DevOps org X, project Y, repository Z, PR 123.”

**All-in-one (review + post):** Use the prompt file [code-review/prompts/review-and-post-pr.md](code-review/prompts/review-and-post-pr.md): it runs the code-review skill, then checks the output JSON and posts comments only if the file contains any threads.

#### How to use the review-and-post-pr prompt

1. **Open the prompt file** in your workspace: `code-review/prompts/review-and-post-pr.md`.
2. **In Cursor chat**, reference it and give the PR link. For example:
   - **"Follow the steps in @code-review/prompts/review-and-post-pr.md and review this PR: \<paste PR link\>."**
   - Or: **"Using @code-review/prompts/review-and-post-pr.md, review and post comments for https://dev.azure.com/my-org/my-project/_git/repo-a/pullrequest/123."**
3. The agent will (1) run the code-review skill and write `code-review/{pr_id}.json`, then (2) read that file and call **post_pr_comments** only if there are comments to post.
4. **Prerequisites:** MCP server running (step 1), token header set in `mcp.json` for your org/project, and (if you use the skill from Cursor skills) the code-review skill copied to `.cursor/skills/code-review/` so the agent can follow the workflow.

### Post PR comments

After a review has produced a comments file, post its contents to the PR using the MCP:

- **Prompt:**  
  **"Post PR comments from @123.json"** (use the actual PR ID as the filename, e.g. @456.json for PR 456)

- Or:  
  **"Let’s post PR comments. Use the comments file for this PR (e.g. @123.json) and post them to this PR."**

You may need to specify provider, org, project, repository, and pull request ID if the agent cannot infer them from context (e.g. from a PR link or the current branch).

---

## Repo structure

- **`code-review/`** — Code review skill (`SKILL.md` + `references/` + `prompts/`). Copy to `.cursor/skills/code-review/`.
- **`mcp/code_reviewer/`** — MCP server for posting PR comment threads, approving/rejecting PRs, and creating PRs. Uses header-only auth (token and reviewer ID in `mcp.json`). See `mcp/code_reviewer/README.md` for tools and Azure DevOps PAT scope.
