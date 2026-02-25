"""
Token store for provider/org (and optional project) credentials.

Stores tokens in a JSON file with restrictive permissions (0o600).
Key format: provider_org or provider_org_project.
"""

import json
import os
from pathlib import Path

SUPPORTED_PROVIDERS = ("azure_devops", "github", "aws")
DEFAULT_CREDENTIALS_DIR = Path.home() / ".pr-comment-mcp"
DEFAULT_CREDENTIALS_FILE = "credentials.json"
ENV_CREDENTIALS_PATH = "PR_COMMENT_CREDENTIALS_PATH"


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


def load_store() -> dict[str, str]:
    """Load the credentials JSON. Returns empty dict if file does not exist."""
    path = _credentials_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_store(store: dict[str, str]) -> None:
    """Write the credentials JSON with mode 0o600."""
    path = _credentials_path()
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def get_token(provider: str, org: str, project: str | None = None) -> str | None:
    """
    Get token for provider/org[/project].
    Tries provider_org_project first if project given, then provider_org.
    """
    store = load_store()
    if project:
        key = _store_key(provider, org, project)
        if key in store:
            return store[key]
    key = _store_key(provider, org, None)
    return store.get(key)


def set_token(
    provider: str,
    org: str,
    token: str,
    project: str | None = None,
) -> None:
    """Store token for provider/org[/project]. Overwrites if key exists."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}. Supported: {SUPPORTED_PROVIDERS}")
    store = load_store()
    store[_store_key(provider, org, project)] = token
    save_store(store)
