#!/usr/bin/env bash
# Remove duplicate /prowler/ blocks and install the correct proxy config.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/etc/nginx/sites-available/nyxstrike"
ENABLED="/etc/nginx/sites-enabled/nyxstrike"
SNIPPET="$ROOT/nyxstrike-prowler.conf.snippet"

if [[ $EUID -ne 0 ]]; then
  echo "Re-run with sudo: sudo bash $0"
  exit 1
fi

python3 - "$TARGET" "$SNIPPET" <<'PY'
import re
import sys
from pathlib import Path

target, snippet_path = sys.argv[1:3]
content = Path(target).read_text()
snippet = Path(snippet_path).read_text().rstrip() + "\n"

# Remove legacy :9443 server block
old_marker = "VRIKA_PROWLER_9443"
if old_marker in content:
    start = content.find(f"# {old_marker}")
    if start != -1:
        brace = content.find("server {", start)
        if brace != -1:
            depth = 0
            end = brace
            for i in range(brace, len(content)):
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            content = content[:start] + content[end:]

# Remove all prowler-related location blocks (duplicates + old wrong config)
patterns = [
    r"\n\s*location = /prowler \{[^}]*\}\n",
    r"\n\s*# VRIKA_PROWLER_443[^\n]*\n",
    r"\n\s*location \^~ /prowler/api/ \{.*?\n    \}\n",
    r"\n\s*location \^~ /prowler/accounts/saml/ \{.*?\n    \}\n",
    r"\n\s*location \^~ /prowler/ \{.*?\n    \}\n",
]
for pat in patterns:
    content = re.sub(pat, "\n", content, flags=re.DOTALL)

anchor = "    location / {"
listen = content.find("listen 443")
if listen == -1:
    raise SystemExit("listen 443 not found")
idx = content.find(anchor, listen)
if idx == -1:
    raise SystemExit("catch-all location / not found")
content = content[:idx] + snippet + content[idx:]
Path(target).write_text(content)
print(f"Cleaned and installed /prowler/ block in {target}")
PY

nginx -t && systemctl reload nginx
echo "OK: https://192.168.9.188/prowler/"
