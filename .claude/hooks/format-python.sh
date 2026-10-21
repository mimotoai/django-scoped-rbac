#!/usr/bin/env bash
# PostToolUse hook: ruff-format and lint-fix Python files after Claude edits them.
#
# Unused imports/variables (F401, F841) are neither removed nor reported here: an
# import is often added one edit before the code that uses it. `uv run ruff check`
# still catches them before commit and in CI. Remaining lint errors are reported back
# to Claude via exit code 2.
set -uo pipefail

file_path=$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("tool_input", {}).get("file_path", ""))')
[[ "$file_path" == *.py && -f "$file_path" ]] || exit 0

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
uv run --quiet ruff format --force-exclude --quiet "$file_path"
if ! output=$(uv run --quiet ruff check --force-exclude --fix --ignore F401,F841 --output-format concise --quiet "$file_path" 2>&1); then
    echo "$output" >&2
    exit 2
fi
exit 0
