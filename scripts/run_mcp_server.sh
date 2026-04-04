#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

export PYTHONPATH="$REPO_ROOT/src"
export DYNAMIQ_MCP_QEMU_USER_PATH="$REPO_ROOT/tools/qemu/qemu-x86_64-instrumented"

exec "$REPO_ROOT/.venv/bin/python" -m dynamiq.mcp_server
