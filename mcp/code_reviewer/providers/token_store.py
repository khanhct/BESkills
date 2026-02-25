"""
Token store for provider/org (and optional project) credentials.

Stores tokens in a JSON file with restrictive permissions (0o600).
Multi-user: keys are scoped by user_id under a "users" object.
Key format per user: provider_org or provider_org_project.
"""

import json
import os
from pathlib import Path

SUPPORTED_PROVIDERS = ("azure_devops", "github", "aws")
DEFAULT_CREDENTIALS_DIR = Path.home() / ".pr-comment-mcp"
DEFAULT_CREDENTIALS_FILE = "credentials.json"
ENV_CREDENTIALS_PATH = "PR_COMMENT_CREDENTIALS_PATH"

# In-memory shape: {"users": {"user_id": {"provider_org_project": "token"}}}
UsersStore = dict[str, dict[str, str]]


def _credentials_path() -> Path:
    path = os.environ.get(ENV_CREDENTIALS_PATH)
    if path:
        return Path(path)
    return DEFAULT_CREDENTIALS_DIR / DEFAULT_CREDENTIALS_FILE


def _store_key(provider: str, org: str, project: str | None = None) -> str:
    if project:
        return f"{provider}_{org}_{project}"
    return f"{provider}_{org}"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_store() -> UsersStore:
    """
    Load the credentials JSON. Returns {"users": {}} if file does not exist.
    Legacy flat format is migrated to users["default"] on first read.
    """
    path = _credentials_path()
    if not path.exists():
        return {"users": {}}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"users": {}}
    if not isinstance(data, dict):
        return {"users": {}}
    # New format: has "users" key
    if "users" in data and isinstance(data["users"], dict):
        return data
    # Legacy flat format: wrap as default user
    return {"users": {"default": data}}


def save_store(store: UsersStore) -> None:
    """Write the credentials JSON with mode 0o600. Expects store with 'users' key."""
    path = _credentials_path()
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def get_token(
    provider: str,
    org: str,
    project: str | None = None,
    user_id: str = "default",
) -> str | None:
    """
    Get token for provider/org[/project] for the given user_id.
    Tries provider_org_project first if project given, then provider_org.
    """
    store = load_store()
    users = store.get("users") or {}
    user_tokens = users.get(user_id) or {}
    if project:
        key = _store_key(provider, org, project)
        if key in user_tokens:
            return user_tokens[key]
    key = _store_key(provider, org, None)
    return user_tokens.get(key)


def set_token(
    provider: str,
    org: str,
    token: str,
    project: str | None = None,
    user_id: str = "default",
) -> None:
    """Store token for provider/org[/project] for the given user_id. Overwrites if key exists."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}. Supported: {SUPPORTED_PROVIDERS}")
    store = load_store()
    if "users" not in store:
        store["users"] = {}
    if user_id not in store["users"]:
        store["users"][user_id] = {}
    store["users"][user_id][_store_key(provider, org, project)] = token
    save_store(store)
