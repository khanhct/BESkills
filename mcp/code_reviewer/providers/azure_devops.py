"""
Azure DevOps provider: create PR comment threads via REST API.

Uses PAT with Authorization: Basic base64(":" + token).
One POST per thread to create threads endpoint.
"""

import base64
from typing import Any

import requests

API_VERSION = "7.1"
BASE_URL = "https://dev.azure.com"


def _auth_header(token: str) -> dict[str, str]:
    # Azure DevOps PAT: empty username, token as password
    encoded = base64.b64encode(f":{token}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _thread_body(thread: dict[str, Any]) -> dict[str, Any]:
    """Build request body for one thread. Ensure leftFileStart/leftFileEnd are null."""
    comments = thread.get("comments", [])
    status = thread.get("status", 1)
    thread_context = thread.get("threadContext") or {}
    # Normalize file path: string, forward slashes; Azure DevOps examples use leading /
    raw_path = (thread_context.get("filePath") or "").replace("\\", "/").strip()
    file_path = ("/" + raw_path.strip("/")) if raw_path else ""
    ctx = {
        "filePath": file_path,
        "leftFileStart": None,
        "leftFileEnd": None,
        "rightFileStart": thread_context.get("rightFileStart"),
        "rightFileEnd": thread_context.get("rightFileEnd"),
    }
    return {
        "comments": comments,
        "status": status,
        "threadContext": ctx,
    }


def post_threads(
    token: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    threads: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Post comment threads to an Azure DevOps pull request.
    One API call per thread.

    Returns:
        {"created": int, "errors": [{"index": int, "message": str}, ...]}
    """
    url = (
        f"{BASE_URL}/{org}/{project}/_apis/git/repositories/{repository}"
        f"/pullRequests/{pull_request_id}/threads?api-version={API_VERSION}"
    )
    headers = {
        **_auth_header(token),
        "Content-Type": "application/json",
    }
    created = 0
    errors: list[dict[str, Any]] = []

    for i, thread in enumerate(threads):
        body = _thread_body(thread)
        try:
            resp = requests.post(url, json=body, headers=headers, timeout=30)
            if resp.status_code == 200:
                created += 1
            else:
                try:
                    err_body = resp.json()
                    msg = err_body.get("message", resp.text) or resp.text
                except Exception:
                    msg = resp.text or f"HTTP {resp.status_code}"
                if resp.status_code == 401:
                    msg = "Invalid or expired token (401). Check your PAT."
                elif resp.status_code == 404:
                    msg = "Not found (404). Check org, project, repository, and PR id."
                elif resp.status_code == 400:
                    msg = f"Bad request (400): {msg}"
                errors.append({"index": i, "message": msg})
        except requests.RequestException as e:
            errors.append({"index": i, "message": str(e)})

    return {"created": created, "errors": errors}


def _ensure_ref(branch: str) -> str:
    """Ensure branch is in refs/heads/ form."""
    s = (branch or "").strip()
    if not s:
        return s
    if s.startswith("refs/"):
        return s
    return f"refs/heads/{s}"


def create_pull_request(
    token: str,
    org: str,
    project: str,
    repository: str,
    source_ref: str,
    target_ref: str,
    title: str,
    description: str | None = None,
) -> dict[str, Any]:
    """
    Create a pull request in Azure DevOps.

    source_ref and target_ref can be branch names (e.g. "feature/xyz", "main") or full refs (refs/heads/main).
    They are normalized to refs/heads/... if not already refs/.

    Returns:
        {"success": bool, "pull_request_id": int | None, "message": str}
    """
    url = (
        f"{BASE_URL}/{org}/{project}/_apis/git/repositories/{repository}"
        f"/pullrequests?api-version={API_VERSION}"
    )
    headers = {
        **_auth_header(token),
        "Content-Type": "application/json",
    }
    body = {
        "sourceRefName": _ensure_ref(source_ref),
        "targetRefName": _ensure_ref(target_ref),
        "title": (title or "").strip() or "Pull Request",
        "description": (description or "").strip() or "",
    }
    try:
        resp = requests.post(url, json=body, headers=headers, timeout=30)
        if resp.status_code in (200, 201):
            data = resp.json()
            pr_id = data.get("pullRequestId") or data.get("pullRequest", {}).get("pullRequestId")
            return {
                "success": True,
                "pull_request_id": pr_id,
                "message": f"Created pull request {pr_id}.",
            }
        try:
            err_body = resp.json()
            msg = err_body.get("message", resp.text) or resp.text
        except Exception:
            msg = resp.text or f"HTTP {resp.status_code}"
        if resp.status_code == 401:
            msg = "Invalid or expired token (401). Check your PAT."
        elif resp.status_code == 404:
            msg = "Not found (404). Check org, project, repository, and branch names."
        elif resp.status_code == 400:
            msg = f"Bad request (400): {msg}"
        return {"success": False, "pull_request_id": None, "message": msg}
    except requests.RequestException as e:
        return {"success": False, "pull_request_id": None, "message": str(e)}


def approve_pull_request(
    token: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    vote: int = 10,
    reviewer_id: str | None = None,
) -> dict[str, Any]:
    """
    Approve a pull request (set reviewer vote).

    reviewer_id is required: pass it via header X-{provider}-{org}-{project}-reviewer-id.
    PUT to the Pull Request Reviewers API with vote (10 = approved, 5 = approved with suggestions,
    0 = no vote, -5 = waiting for author, -10 = rejected).

    Returns:
        {"success": bool, "message": str}
    """
    if not reviewer_id or not str(reviewer_id).strip():
        return {
            "success": False,
            "message": "reviewer_id is required. Set header X-{provider}-{org}-{project}-reviewer-id or X-PR-Reviewer-Id, or pass the reviewer_id parameter.",
        }
    reviewer_id = str(reviewer_id).strip()
    headers = {
        **_auth_header(token),
        "Content-Type": "application/json",
    }
    url = (
        f"{BASE_URL}/{org}/{project}/_apis/git/repositories/{repository}"
        f"/pullRequests/{pull_request_id}/reviewers/{reviewer_id}?api-version={API_VERSION}"
    )
    body = {"vote": vote, "id": reviewer_id}
    try:
        resp = requests.put(url, json=body, headers=headers, timeout=30)
        if resp.status_code == 200:
            return {"success": True, "message": f"PR {pull_request_id} approved (vote={vote})."}
        try:
            err_body = resp.json()
            msg = err_body.get("message", resp.text) or resp.text
        except Exception:
            msg = resp.text or f"HTTP {resp.status_code}"
        if resp.status_code == 401:
            msg = "Invalid or expired token (401). Check your PAT."
        elif resp.status_code == 404:
            msg = "Not found (404). Check org, project, repository, and PR id."
        return {"success": False, "message": msg}
    except requests.RequestException as e:
        return {"success": False, "message": str(e)}
