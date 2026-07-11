#!/usr/bin/env bash
# Fix stale :9443 URLs in server .env → https://HOST/prowler on :443
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
HOST="${VRIKA_HOST:-192.168.9.188}"
BASE="https://${HOST}/prowler"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"

python3 - "$ENV_FILE" "$BASE" "$HOST" <<'PY'
import re
import sys
from pathlib import Path

path, base, host = sys.argv[1:4]
text = Path(path).read_text()

replacements = {
    r'^AUTH_URL=.*$': f'AUTH_URL={base}',
    r'^NEXT_PUBLIC_BASE_PATH=.*$': 'NEXT_PUBLIC_BASE_PATH=/prowler',
    r'^UI_API_BASE_URL=.*$': f'UI_API_BASE_URL={base}/api/v1',
    r'^NEXT_PUBLIC_API_BASE_URL=.*$': f'NEXT_PUBLIC_API_BASE_URL={base}/api/v1',
    r'^UI_API_DOCS_URL=.*$': f'UI_API_DOCS_URL={base}/api/v1/docs',
    r'^NEXT_PUBLIC_API_DOCS_URL=.*$': f'NEXT_PUBLIC_API_DOCS_URL={base}/api/v1/docs',
    r'^SOCIAL_GOOGLE_OAUTH_CALLBACK_URL=.*$': f'SOCIAL_GOOGLE_OAUTH_CALLBACK_URL={base}/api/auth/callback/google',
    r'^SOCIAL_GITHUB_OAUTH_CALLBACK_URL=.*$': f'SOCIAL_GITHUB_OAUTH_CALLBACK_URL={base}/api/auth/callback/github',
    r'^SAML_SSO_CALLBACK_URL=.*$': f'SAML_SSO_CALLBACK_URL={base}/api/auth/callback/saml',
}

for pattern, value in replacements.items():
    if re.search(pattern, text, flags=re.M):
        text = re.sub(pattern, value, text, flags=re.M)
    elif 'NEXT_PUBLIC_BASE_PATH' in pattern:
        text += f'\nNEXT_PUBLIC_BASE_PATH=/prowler\n'

# CORS: drop :9443, keep host https origin
text = re.sub(
    r'^DJANGO_CORS_ALLOWED_ORIGINS=.*$',
    f'DJANGO_CORS_ALLOWED_ORIGINS=https://{host},http://127.0.0.1:8090',
    text,
    flags=re.M,
)

Path(path).write_text(text)
print(f"Updated {path} — AUTH_URL={base}")
PY

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"
$COMPOSE up -d ui api worker worker-beat nginx --force-recreate

echo "Verify:"
sleep 10
curl -sk -I "https://${HOST}/prowler/findings" | grep -i location || true
echo "Open: https://${HOST}/prowler/sign-in"
