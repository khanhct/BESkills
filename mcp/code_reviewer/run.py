"""
Uvicorn entrypoint for the PR Comment MCP server.

Exposes the FastMCP HTTP app for deployment with uvicorn.

Run:
  uv run python run.py
  uv run uvicorn run:app --host 0.0.0.0 --port 8000
  uv run uvicorn run:app --host 0.0.0.0 --port 8000 --reload  # development
"""

from server import mcp

app = mcp.http_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "run:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
