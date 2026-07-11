#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/etc/nginx/sites-available/nyxstrike"
MARKER="VRIKA_PROWLER_443"
OLD_MARKER="VRIKA_PROWLER_9443"
SNIPPET="$ROOT/nyxstrike-prowler.conf.snippet"

if [[ $EUID -ne 0 ]]; then
  echo "Re-run with sudo: sudo bash $0"
  exit 1
fi

python3 - "$TARGET" "$SNIPPET" "$MARKER" "$OLD_MARKER" <<'PY'
import sys
from pathlib import Path
target, snippet_path, marker, old_marker = sys.argv[1:5]
content = Path(target).read_text()
snippet = Path(snippet_path).read_text().rstrip() + "\n"
if old_marker in content:
    start = content.find(f"# {old_marker}")
    if start != -1:
        brace = content.find("server {", start)
        if brace != -1:
            depth = 0
            end = brace
            for i in range(brace, len(content)):
                if content[i] == "{": depth += 1
                elif content[i] == "}": 
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            content = content[:start] + content[end:]
if marker in content:
    print(f"Already configured in {target}")
else:
    anchor = "    location / {"
    listen = content.find("listen 443")
    if listen == -1:
        raise SystemExit("listen 443 not found")
    idx = content.find(anchor, listen)
    if idx == -1:
        raise SystemExit("catch-all location / not found")
    Path(target).write_text(content[:idx] + snippet + content[idx:])
    print(f"Inserted /prowler/ into {target}")
PY

nginx -t && systemctl reload nginx
echo "Prowler: https://192.168.9.188/prowler/"
