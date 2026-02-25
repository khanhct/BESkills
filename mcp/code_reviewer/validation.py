"""
Validate comments_body against pr-comment-format.md schema.

- Root is an array of thread objects.
- Each thread: exactly one comment, status === 1, threadContext with filePath (leading /), rightFileStart, rightFileEnd.
"""

import json
from typing import Any


def _validate_position(pos: Any, name: str) -> list[str]:
    errs = []
    if not isinstance(pos, dict):
        errs.append(f"{name}: must be an object with line and offset")
        return errs
    if "line" not in pos or not isinstance(pos["line"], int):
        errs.append(f"{name}: missing or invalid 'line' (1-based integer)")
    if "offset" not in pos or not isinstance(pos["offset"], int):
        errs.append(f"{name}: missing or invalid 'offset' (1-based integer)")
    return errs


def validate_thread(thread: Any, index: int) -> list[str]:
    """Validate a single thread. Returns list of error messages."""
    errs: list[str] = []
    if not isinstance(thread, dict):
        return [f"Thread {index}: must be an object"]
    comments = thread.get("comments")
    if not isinstance(comments, list):
        errs.append(f"Thread {index}: 'comments' must be an array")
    elif len(comments) != 1:
        errs.append(f"Thread {index}: must have exactly one comment in 'comments'")
    else:
        c = comments[0]
        if not isinstance(c, dict):
            errs.append(f"Thread {index}: comment must be an object")
        else:
            if "content" not in c or not isinstance(c.get("content"), str):
                errs.append(f"Thread {index}: comment must have 'content' string")
            if c.get("parentCommentId", 0) != 0:
                errs.append(f"Thread {index}: top-level comment should have parentCommentId 0")
            if c.get("commentType", 1) != 1:
                errs.append(f"Thread {index}: commentType should be 1")
    if thread.get("status") != 1:
        errs.append(f"Thread {index}: 'status' must be 1 (active)")
    ctx = thread.get("threadContext")
    if not isinstance(ctx, dict):
        errs.append(f"Thread {index}: 'threadContext' must be an object")
    else:
        fp = ctx.get("filePath")
        if not isinstance(fp, str) or not fp.startswith("/"):
            errs.append(f"Thread {index}: threadContext.filePath must start with / and use forward slashes")
        errs.extend(_validate_position(ctx.get("rightFileStart"), f"Thread {index}.threadContext.rightFileStart"))
        errs.extend(_validate_position(ctx.get("rightFileEnd"), f"Thread {index}.threadContext.rightFileEnd"))
    return errs


def validate_comments_body(comments_body: str) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """
    Parse and validate the JSON array of threads.
    Returns (threads, errors). If errors non-empty, threads may be None or partial.
    """
    errs: list[str] = []
    try:
        data = json.loads(comments_body)
    except ValueError as e:
        return None, [f"Invalid JSON: {e}"]
    if not isinstance(data, list):
        return None, ["Root must be a JSON array of thread objects"]
    threads: list[dict[str, Any]] = []
    for i, item in enumerate(data):
        te = validate_thread(item, i)
        if te:
            errs.extend(te)
        else:
            threads.append(item)
    return threads, errs
