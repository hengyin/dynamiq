"""Compatibility module alias for interactive_analysis.mcp_server."""

from interactive_analysis.mcp_server import *  # noqa: F401,F403
from interactive_analysis.mcp_server import main


if __name__ == "__main__":
    raise SystemExit(main())
