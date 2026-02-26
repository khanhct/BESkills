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
    # API sample uses leftFileEnd/leftFileStart null for right-side-only
    ctx = {
        "filePath": thread_context.get("filePath", ""),
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


def approve_pull_request(
    token: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    vote: int = 10,
) -> dict[str, Any]:
    """
    Approve a pull request (set reviewer vote for the authenticated user).

    Uses ConnectionData to get the current user's identity id, then PUT to the
    Pull Request Reviewers API with vote (10 = approved, 5 = approved with suggestions,
    0 = no vote, -5 = waiting for author, -10 = rejected).

    Returns:
        {"success": bool, "message": str}
    """
    headers = {
        **_auth_header(token),
        "Content-Type": "application/json",
    }
    # Get current user id from connection data
    connection_url = f"{BASE_URL}/{org}/_apis/connectiondata?api-version={API_VERSION}"
    try:
        conn_resp = requests.get(connection_url, headers=headers, timeout=30)
        if conn_resp.status_code != 200:
            return {
                "success": False,
                "message": f"Failed to get current user: HTTP {conn_resp.status_code}. Check PAT and org.",
            }
        conn_data = conn_resp.json()
        authenticated_user = conn_data.get("authenticatedUser") or conn_data.get("authorizedUser")
        if not authenticated_user:
            return {"success": False, "message": "ConnectionData did not return authenticated user."}
        reviewer_id = authenticated_user.get("id")
        if not reviewer_id:
            return {"success": False, "message": "Authenticated user has no id."}
    except requests.RequestException as e:
        return {"success": False, "message": f"Failed to get current user: {e}"}

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
