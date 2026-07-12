#!/usr/bin/env bash
# Sync OpenRouter LLM vars from vrika-agent into vrika-cloud-security .env
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
AGENT_ENV="${VRIKA_AGENT_ENV:-$HOME/vrika-agent/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE" >&2
  exit 1
fi

if [[ ! -f "$AGENT_ENV" ]]; then
  echo "Missing $AGENT_ENV" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$AGENT_ENV"
set +a

python3 - "$ENV_FILE" <<'PY'
import re
import sys
from pathlib import Path

env_path = Path(sys.argv[1])
text = env_path.read_text()

import os

updates = {
    "VRIKA_LLM_API_KEY": os.environ.get("VRIKA_LLM_API_KEY", ""),
    "VRIKA_LLM_URL": os.environ.get("VRIKA_LLM_URL", "https://openrouter.ai/api/v1"),
    "VRIKA_LLM_MODEL": os.environ.get("VRIKA_LLM_MODEL", "openai/gpt-4.1-mini"),
    "VRIKA_LLM_PROVIDER": os.environ.get("VRIKA_LLM_PROVIDER", "openrouter"),
    "VRIKA_LIGHTHOUSE_PROVIDER": "openai_compatible",
    "VRIKA_LIGHTHOUSE_BASE_URL": os.environ.get(
        "VRIKA_LLM_URL", "https://openrouter.ai/api/v1"
    ),
    "VRIKA_LIGHTHOUSE_MODEL": os.environ.get(
        "VRIKA_LLM_MODEL", "openai/gpt-4.1-mini"
    ),
    "VRIKA_LIGHTHOUSE_OPENAI_API_KEY": os.environ.get("VRIKA_LLM_API_KEY", ""),
}

for key, value in updates.items():
    if not value:
        continue
    pattern = rf"^{re.escape(key)}=.*$"
    line = f"{key}={value}"
    if re.search(pattern, text, flags=re.M):
        text = re.sub(pattern, line, text, flags=re.M)
    else:
        text = text.rstrip() + "\n" + line + "\n"

env_path.write_text(text)
print(f"Updated {env_path} for OpenRouter")
PY
