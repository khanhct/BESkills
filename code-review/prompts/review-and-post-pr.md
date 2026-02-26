# Review PR and Post Comments

Use this prompt to run a full code review and, when there are findings, post them as PR comments.

---

## Steps

### Step 1: Review the PR using the code-review skill

1. **Invoke the code-review skill** to review the pull request.
   - Provide the PR link (e.g. `https://dev.azure.com/<org>/<project>/_git/<repo>/pullrequest/<id>`).
   - Or specify org, project, repository, and pull request ID if the link is not available.

2. **Follow the code-review workflow** (see [SKILL.md](SKILL.md)):
   - Pull latest target and PR branches in the mapped repo(s).
   - Compute the diff and review changed files using the skill’s evaluation criteria and focus areas.
   - Produce the **comments JSON file** at `code-review/{pr_id}.json` (e.g. `code-review/123.json` for PR 123).
   - The file must be a JSON array of thread objects. If there are no comments, the file must be `[]`.

3. **Confirm the output file**  
   After the review, note the path of the generated file (e.g. `code-review/123.json`) and whether it contains any threads.

---

### Step 2: Check the output JSON and post comments if any

1. **Read the output file**  
   Open the comments file written in Step 1 (e.g. `code-review/123.json`).

2. **Check for comments**
   - If the file is an empty array `[]` or has no elements → **do not post**. Inform the user: “Review complete; no comments to post.”
   - If the file contains one or more thread objects → proceed to post.

3. **Post comments to the PR**
   - Use the **post_pr_comments** MCP tool with:
     - **provider**: `azure` (for Azure DevOps)
     - **org**, **project**, **repository**, **pull_request_id**: from the PR link or user context
     - **comments_body**: the full JSON array from the file as a string (ensure valid JSON)
   - Token must be set via header `X-azure-<org>-<project>-token` in MCP config (see [README](../../README.md)).
   - If posting succeeds, report how many threads were created. If some fail, report the errors from the tool response.

4. **Optional cleanup**  
   If the code-review skill checked out a local PR branch, you may switch back to the target branch and delete the PR branch (see SKILL.md “Cleanup”).

---

## Example user prompts

- *“Review this PR and post comments if there are any: https://dev.azure.com/my-org/my-project/_git/repo-a/pullrequest/456.”*
- *“Using the code-review skill, review PR 789 in repo-a, then check the output JSON and post the comments to the PR.”*

---

## Summary

| Step | Action |
|------|--------|
| 1   | Use code-review skill to review the PR and write `code-review/{pr_id}.json`. |
| 2   | Read the JSON file; if it has at least one thread, call **post_pr_comments** with that JSON; otherwise do not post. |
