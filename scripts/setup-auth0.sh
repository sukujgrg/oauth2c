#!/usr/bin/env bash
# Provision oauth2c demo apps, an API, and a test user on the active Auth0
# tenant. Re-runnable: existing resources with the same names are updated.
#
# Prerequisites:
#   A free Auth0 tenant (https://manage.auth0.com/)
#   brew install auth0
#   auth0 login
#   auth0 tenants use <your-tenant>.auth0.com
#
# Optional extra Management API scopes if client grants or tenant settings fail:
#   auth0 login --scopes "create:client_grants,read:client_grants,update:tenant_settings,read:connections,update:connections,update:users"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="oauth2c"
AUDIENCE="https://oauth2c.local"
CALLBACK="http://localhost:9876/callback"
CALLBACK_TLS="https://localhost:9876/callback"
EMAIL="oauth2c-demo@example.com"
ENV_FILE="$ROOT/.env.auth0"
TENANT="${AUTH0_DOMAIN:-}"
API_SCOPE="demo:read"

usage() {
  cat <<'EOF'
Usage: scripts/setup-auth0.sh [options]

Prerequisite: a free Auth0 tenant at https://manage.auth0.com/

  --tenant DOMAIN     Auth0 tenant domain (default: active CLI tenant)
  --audience URI      API identifier / oauth2c --audience (default: https://oauth2c.local)
  --callback URL      Browser callback (default: http://localhost:9876/callback)
  --email ADDRESS     Demo user email for the password grant
  --env-file PATH     Where to write secrets (default: .env.auth0, gitignored)
  --prefix NAME       Resource name prefix (default: oauth2c)
  -h, --help          Show this help

The script writes client IDs and secrets to --env-file. Do not commit that file.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant) TENANT="$2"; shift 2 ;;
    --audience) AUDIENCE="$2"; shift 2 ;;
    --callback) CALLBACK="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need auth0
need python3
need openssl

auth0_base=(auth0 --no-input --no-color)
if [[ -n "$TENANT" ]]; then
  auth0_base+=(--tenant "$TENANT")
fi

# Auth0 CLI sometimes prints a banner before JSON. Take the first JSON value.
extract_json() {
  python3 -c '
import json, sys
raw = sys.stdin.read()
for i, ch in enumerate(raw):
    if ch in "{[":
        json.dump(json.loads(raw[i:]), sys.stdout)
        break
else:
    sys.stderr.write("no JSON in command output\n")
    sys.stderr.write(raw[:1000])
    sys.exit(1)
'
}

auth0_json() {
  local out
  out="$("${auth0_base[@]}" "$@" )"
  printf '%s' "$out" | extract_json
}

json_get() {
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); p=sys.argv[2].split(".");
v=d
for k in p:
    if isinstance(v, list):
        v=v[int(k)]
    else:
        v=v.get(k)
    if v is None:
        print(""); sys.exit(0)
if isinstance(v,(dict,list)):
    json.dump(v, sys.stdout)
else:
    print(v)
' "$1" "$2"
}

if [[ -z "$TENANT" ]]; then
  TENANT="$(auth0_json tenants list --json | python3 -c '
import json,sys
tenants=json.load(sys.stdin)
active=next((t["name"] for t in tenants if t.get("active")), None)
if not active:
    sys.stderr.write("no active Auth0 tenant; run: auth0 login && auth0 tenants use <domain>\n")
    sys.exit(1)
print(active)
')"
  auth0_base+=(--tenant "$TENANT")
fi

ISSUER="https://${TENANT}"
ISSUER="${ISSUER%/}"

echo "Using tenant ${TENANT}"
echo "Issuer        ${ISSUER}"
echo "API audience  ${AUDIENCE}"
echo "Callback      ${CALLBACK}"

NAME_API="${PREFIX}-api"
NAME_WEB="${PREFIX}-web"
NAME_POST="${PREFIX}-m2m"
NAME_SPA="${PREFIX}-spa"
NAME_DEVICE="${PREFIX}-device"

ensure_api() {
  local apis id
  apis="$(auth0_json apis list --json)"
  id="$(python3 -c '
import json,sys
apis=json.loads(sys.argv[1])
name, aud = sys.argv[2], sys.argv[3]
for a in apis:
    if a.get("name")==name or a.get("identifier")==aud:
        print(a.get("id") or a.get("identifier") or "")
        break
' "$apis" "$NAME_API" "$AUDIENCE")"

  if [[ -n "$id" ]]; then
    echo "Updating API ${NAME_API}" >&2
    auth0_json apis update "$id" \
      --name "$NAME_API" \
      --offline-access=true \
      --scopes "$API_SCOPE" \
      --json >/dev/null
  else
    echo "Creating API ${NAME_API}" >&2
    if ! auth0_json apis create \
      --name "$NAME_API" \
      --identifier "$AUDIENCE" \
      --offline-access=true \
      --scopes "$API_SCOPE" \
      --subject-type-authorization '{"user":{"policy":"allow_all"},"client":{"policy":"require_client_grant"}}' \
      --json >/dev/null; then
      echo "Retrying API create without subject-type-authorization" >&2
      auth0_json apis create \
        --name "$NAME_API" \
        --identifier "$AUDIENCE" \
        --offline-access=true \
        --scopes "$API_SCOPE" \
        --json >/dev/null
    fi
  fi
}

find_app() {
  python3 -c '
import json,sys
apps=json.loads(sys.argv[1])
name=sys.argv[2]
for a in apps:
    if a.get("name")==name:
        print(a.get("client_id",""))
        break
' "$1" "$2"
}

ensure_app() {
  local name="$1" type="$2" method="$3" grants="$4"
  local apps id created
  apps="$(auth0_json apps list --json)"
  id="$(find_app "$apps" "$name")"

  if [[ -n "$id" ]]; then
    echo "Updating app ${name} (${id})" >&2
    auth0_json apps update "$id" \
      --name "$name" \
      --type "$type" \
      --auth-method "$method" \
      --callbacks "${CALLBACK},${CALLBACK_TLS}" \
      --logout-urls "${CALLBACK},${CALLBACK_TLS}" \
      --origins "http://localhost:9876,https://localhost:9876" \
      --web-origins "http://localhost:9876,https://localhost:9876" \
      --grants "$grants" \
      --metadata "oauth2c=true" \
      --json >/dev/null
  else
    echo "Creating app ${name}" >&2
    created="$(auth0_json apps create \
      --name "$name" \
      --description "oauth2c README demo (${type})" \
      --type "$type" \
      --auth-method "$method" \
      --callbacks "${CALLBACK},${CALLBACK_TLS}" \
      --logout-urls "${CALLBACK},${CALLBACK_TLS}" \
      --origins "http://localhost:9876,https://localhost:9876" \
      --web-origins "http://localhost:9876,https://localhost:9876" \
      --grants "$grants" \
      --metadata "oauth2c=true" \
      --reveal-secrets \
      --json)"
    id="$(json_get "$created" "client_id")"
  fi
  printf '%s' "$id"
}

app_secret() {
  local shown
  shown="$(auth0_json apps show "$1" --reveal-secrets --json)"
  json_get "$shown" "client_secret"
}

ensure_client_grant() {
  local client_id="$1"
  local grants existing
  grants="$(auth0_json api get client-grants)"
  existing="$(python3 -c '
import json,sys
grants=json.loads(sys.argv[1])
cid, aud = sys.argv[2], sys.argv[3]
items=grants if isinstance(grants, list) else grants.get("client_grants", [])
for g in items:
    if g.get("client_id")==cid and g.get("audience")==aud:
        print(g.get("id",""))
        break
' "$grants" "$client_id" "$AUDIENCE")"
  if [[ -n "$existing" ]]; then
    echo "Client grant already exists for ${client_id}" >&2
    return 0
  fi
  echo "Creating client grant ${client_id} -> ${AUDIENCE}" >&2
  if ! "${auth0_base[@]}" api post client-grants --data "$(python3 -c '
import json,sys
print(json.dumps({"client_id":sys.argv[1],"audience":sys.argv[2],"scope":[sys.argv[3]]}))
' "$client_id" "$AUDIENCE" "$API_SCOPE")" >/dev/null; then
    echo "warning: could not create client grant for ${client_id}." >&2
    echo "  Re-login with: auth0 login --scopes create:client_grants,read:client_grants" >&2
  fi
}

CONN_JSON="$(auth0_json api get connections)"
CONN_ID="$(python3 -c '
import json,sys
conns=json.loads(sys.argv[1])
items=conns if isinstance(conns, list) else []
db=next((c for c in items if c.get("strategy")=="auth0"), None)
if not db:
    raise SystemExit("no Username-Password database connection on this tenant")
print(db["id"])
' "$CONN_JSON")"
CONN_NAME="$(python3 -c '
import json,sys
conns=json.loads(sys.argv[1])
items=conns if isinstance(conns, list) else []
db=next((c for c in items if c.get("strategy")=="auth0"), None)
print(db["name"])
' "$CONN_JSON")"
echo "Database connection ${CONN_NAME} (${CONN_ID})" >&2

enable_client_on_connection() {
  local client_id="$1"
  local current
  current="$(auth0_json api get "connections/${CONN_ID}/clients")"
  if python3 -c '
import json,sys
data=json.loads(sys.argv[1])
cid=sys.argv[2]
clients=data.get("clients", data if isinstance(data, list) else [])
ids=[c.get("client_id", c) if isinstance(c, dict) else c for c in clients]
sys.exit(0 if cid in ids else 1)
' "$current" "$client_id"; then
    echo "Connection already enables ${client_id}" >&2
    return 0
  fi
  echo "Enabling ${client_id} on ${CONN_NAME}" >&2
  if ! "${auth0_base[@]}" api post "connections/${CONN_ID}/clients" --data "$(python3 -c '
import json,sys
print(json.dumps({"clients":[{"client_id":sys.argv[1],"status":True}]}))
' "$client_id")" >/dev/null; then
    echo "warning: could not enable ${client_id} on ${CONN_NAME}." >&2
    echo "  Enable it in Dashboard > Authentication > Database > ${CONN_NAME} > Applications." >&2
  fi
}

ensure_default_directory() {
  local settings current
  settings="$(auth0_json api get tenants/settings || true)"
  if [[ -z "$settings" ]]; then
    echo "warning: could not read tenant settings; password grant may need a default directory." >&2
    return 0
  fi
  current="$(json_get "$settings" "default_directory")"
  if [[ -z "$current" ]]; then
    echo "Setting tenant default_directory to ${CONN_NAME} (needed for the password grant)" >&2
    if ! "${auth0_base[@]}" api patch tenants/settings --data "$(python3 -c '
import json,sys
print(json.dumps({"default_directory":sys.argv[1]}))
' "$CONN_NAME")" >/dev/null; then
      echo "warning: could not set default_directory. Password grant may fail." >&2
      echo "  Re-login with: auth0 login --scopes update:tenant_settings" >&2
    fi
  elif [[ "$current" != "$CONN_NAME" ]]; then
    echo "warning: tenant default_directory is ${current}, not ${CONN_NAME}." >&2
    echo "  oauth2c --grant-type password uses the tenant default directory." >&2
  else
    echo "Tenant default_directory already ${CONN_NAME}" >&2
  fi
}

existing_password=""
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  existing_password="$(python3 -c '
import re,sys
text=open(sys.argv[1]).read()
m=re.search(r"^OAUTH2C_PASSWORD=(.*)$", text, re.M)
print(m.group(1).strip().strip("\"'\''") if m else "")
' "$ENV_FILE")"
fi

PASSWORD="${existing_password:-}"
if [[ -z "$PASSWORD" ]]; then
  PASSWORD="Aa1!$(openssl rand -base64 18 | tr -d '/+=' | head -c 18)"
fi

ensure_user() {
  local found id
  found="$(auth0_json users search-by-email "$EMAIL" --json)"
  id="$(python3 -c '
import json,sys
users=json.loads(sys.argv[1])
if isinstance(users, list) and users:
    print(users[0].get("user_id",""))
' "$found")"
  if [[ -n "$id" ]]; then
    echo "Updating demo user ${EMAIL}" >&2
    "${auth0_base[@]}" users update "$id" --password "$PASSWORD" >/dev/null
  else
    echo "Creating demo user ${EMAIL}" >&2
    id="$(json_get "$(auth0_json users create \
      --name "oauth2c demo" \
      --email "$EMAIL" \
      --password "$PASSWORD" \
      --connection-name "$CONN_NAME" \
      --json)" "user_id")"
  fi
  if [[ -n "$id" ]]; then
    "${auth0_base[@]}" api patch "users/${id}" --data '{"email_verified":true}' >/dev/null || true
  fi
}

warn_credentials_exchange_actions() {
  local bindings names
  bindings="$(auth0_json api get actions/triggers/credentials-exchange/bindings 2>/dev/null || true)"
  [[ -z "$bindings" ]] && return 0
  names="$(python3 -c '
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    raise SystemExit(0)
items=data.get("bindings", []) if isinstance(data, dict) else []
print("\n".join(b.get("display_name") or (b.get("action") or {}).get("name","") for b in items if b))
' "$bindings")"
  if [[ -n "$names" ]]; then
    echo "warning: credentials-exchange Actions are bound on this tenant:" >&2
    echo "$names" | sed 's/^/  - /' >&2
    echo "  They run on every client-credentials request, including oauth2c demos." >&2
  fi
}

warn_credentials_exchange_actions
ensure_api

WEB_ID="$(ensure_app "$NAME_WEB" regular Basic "code,implicit,refresh-token,credentials,password,password-realm")"
POST_ID="$(ensure_app "$NAME_POST" m2m Post "credentials")"
SPA_ID="$(ensure_app "$NAME_SPA" spa None "code,implicit,refresh-token")"
DEVICE_ID="$(ensure_app "$NAME_DEVICE" native None "code,refresh-token,device-code")"

WEB_SECRET="$(app_secret "$WEB_ID")"
POST_SECRET="$(app_secret "$POST_ID")"

ensure_client_grant "$WEB_ID"
ensure_client_grant "$POST_ID"
ensure_client_grant "$SPA_ID"
ensure_client_grant "$DEVICE_ID"

enable_client_on_connection "$WEB_ID"
enable_client_on_connection "$SPA_ID"
enable_client_on_connection "$DEVICE_ID"

ensure_default_directory
ensure_user

umask 077
cat >"$ENV_FILE" <<EOF
# Generated by scripts/setup-auth0.sh for ${TENANT}
# Do not commit this file.

OAUTH2C_ISSUER=${ISSUER}
OAUTH2C_AUDIENCE=${AUDIENCE}
OAUTH2C_CALLBACK=${CALLBACK}
OAUTH2C_SCOPE=${API_SCOPE}

OAUTH2C_WEB_CLIENT_ID=${WEB_ID}
OAUTH2C_WEB_CLIENT_SECRET=${WEB_SECRET}

OAUTH2C_POST_CLIENT_ID=${POST_ID}
OAUTH2C_POST_CLIENT_SECRET=${POST_SECRET}

OAUTH2C_SPA_CLIENT_ID=${SPA_ID}
OAUTH2C_DEVICE_CLIENT_ID=${DEVICE_ID}

OAUTH2C_USERNAME=${EMAIL}
OAUTH2C_PASSWORD=${PASSWORD}
EOF

echo
echo "Wrote ${ENV_FILE}"
echo "Load it with:  set -a && source ${ENV_FILE} && set +a"
echo
echo "Smoke-test client credentials:"
echo "  oauth2c \"\$OAUTH2C_ISSUER\" --grant-type client_credentials --auth-method client_secret_basic \\"
echo "    --client-id \"\$OAUTH2C_WEB_CLIENT_ID\" --client-secret \"\$OAUTH2C_WEB_CLIENT_SECRET\" \\"
echo "    --audience \"\$OAUTH2C_AUDIENCE\" --scopes \"\$OAUTH2C_SCOPE\" --silent"
