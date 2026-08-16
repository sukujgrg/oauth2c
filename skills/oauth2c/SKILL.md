---
name: oauth2c
description: >-
  Drive the oauth2c CLI to test and validate OAuth 2.0 / OIDC apps against
  a real authorization server. Use when validating an OAuth/OIDC app,
  running grants, fetching tokens, checking PKCE, nonce, PAR, DPoP, or a
  loopback callback, or diagnosing protocol failures with oauth2c.
license: Apache-2.0
---

# oauth2c

Flag-driven OAuth 2.0 / OIDC client. No prompts. Token JSON on stdout.
JSON lines on stderr (protocol trace and CLI errors). Traces dump
secrets; not a production client.

Install (no Go required). Pin the binary to this skill's tag:

```sh
OAUTH2C_VERSION=v2.1.0 curl -fsSL https://raw.githubusercontent.com/sukujgrg/oauth2c/v2.1.0/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
$env:OAUTH2C_VERSION = "v2.1.0"
irm https://raw.githubusercontent.com/sukujgrg/oauth2c/v2.1.0/scripts/install.ps1 | iex
```

Or download a release from https://github.com/sukujgrg/oauth2c/releases

Install this skill (GitHub CLI v2.90+):

```sh
gh skill install sukujgrg/oauth2c oauth2c@v2.1.0
```

## Workflow

Validate the client you were given. Getting a token is one possible
outcome, not the goal.

1. `oauth2c version` — need `2.1.0` or later, not `2.0.x`. Missing or
   too old → install with the command above (release binary, not
   `go install`).
2. Inputs: issuer (no trailing slash), `client_id`, and for interactive
   grants the **exact registered** redirect URI. `.env.auth0` is
   optional demo setup only. An empty flag value exits 1.
3. Ask client type (confidential or public) and which grants it may
   use. Pick the probe from that. Do not invent a new client.
4. Write artifacts under a 0700 temp dir, never the repo:

   ```sh
   out=$(mktemp -d)
   chmod 700 "$out"
   oauth2c … >"$out/token.json" 2>"$out/trace.jsonl"
   ```

5. Keep stdout and stderr separate. Do not use `2>&1`. First run: no
   `--silent`. Later runs may add `--silent` if you only need token JSON.
6. Interpret the exit code against the **expected** outcome. Exit 1 is a
   pass when the grant was a negative probe (public client
   `client_credentials` returning `unauthorized_client`). “Fix flags
   and rerun” only when the grant was supposed to succeed. A failed
   `check id_token.nonce` with `received` `(missing)` can still exit 0.

```
oauth2c <issuer-url-or-json-file> --grant-type <type> [flags] >token.json 2>trace.jsonl
```

- `--grant-type` is required.
- stderr is JSON lines. Parse each line as one object. `--silent` drops
  the protocol trace; `error` events still appear. Stdout is always
  token JSON. `--help` is human text on stdout.
- Issuer: no trailing slash. oauth2c appends
  `/.well-known/openid-configuration`.
- First arg may be a JSON file: `client_id`, `client_secret`,
  `openid_discovery_endpoint`. Flags override the file.
- List flags (`--scopes`, `--audience`, `--response-types`) are
  comma-separated.
- `--redirect-url` (alias `--redirect-uri`) is the `redirect_uri` sent
  to the authorization server. `--callback-addr` is the local bind
  (`host:port`). If
  `--callback-addr` is omitted, the process binds to the host:port of
  `--redirect-url`. Default `http://localhost:9876/callback` is usually
  wrong (`localhost` vs `127.0.0.1`, path, port). Do not pass `:0`; this
  CLI sets `redirect_uri` before listen.
- Timeouts: `--http-timeout 1m`, `--browser-timeout 10m`.

## Pick a probe

| Client | Unattended? | Probe |
| --- | --- | --- |
| confidential, `client_credentials` allowed | yes | `client_credentials` with secret |
| confidential, user login | needs human | `authorization_code` |
| public (native, SPA, CLI) | needs human | `authorization_code` + PKCE (recipe below) |
| public, device | needs human | `urn:ietf:params:oauth:grant-type:device_code`, `--auth-method none` |
| public, `client_credentials` forbidden | yes | `client_credentials` **expected fail** |

`--pkce` on `authorization_code` (required for public clients). When you
expect an ID token (`openid` scope or `id_token` response type): pass
`--nonce` with a known value. Do not add PKCE or nonce on
`client_credentials`.

An access token may be a signed JWT, opaque, or JWE. Trace labels
`(opaque)` and `(jwe)` are still a successful token response. Pass
`--audience` only when the user or the authorization server requires a
token for a specific resource.

Interactive grants: if a human is present, do **not** pass
`--no-browser`. Print `authorization_url` / `verification_url`, tell
them to finish at the authorization server, set `--browser-timeout`
(default `10m` is finite), then wait. `--no-browser` only skips opening
the URL; it still waits. Do not start `authorization_code`, `implicit`,
or `urn:ietf:params:oauth:grant-type:device_code` unattended.

## Grants

| `--grant-type` | Human? | Typical extra flags |
| --- | --- | --- |
| `client_credentials` | no | `--client-id --client-secret --auth-method` |
| `password` | no | `--client-id --client-secret --auth-method --username --password` |
| `refresh_token` | no | `--client-id --client-secret --auth-method --refresh-token` |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | no | `--client-id --client-secret --auth-method --assertion --signing-key` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | no | `--client-id --client-secret --auth-method --subject-token --subject-token-type` |
| `authorization_code` | yes | `--client-id --auth-method --response-types code --response-mode query` |
| `implicit` | yes | `--client-id --auth-method none --response-types token` or `id_token` |
| `urn:ietf:params:oauth:grant-type:device_code` | yes | `--client-id --auth-method none` |

Hybrid: `--grant-type authorization_code --response-types code,id_token`.

Confidential unattended (only if this client may use CC):

```sh
oauth2c "$ISSUER" \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --client-id "$CLIENT_ID" \
  --client-secret "$CLIENT_SECRET" \
  >"$out/token.json" 2>"$out/trace.jsonl"
```

Public `authorization_code` (human present; use the **exact** registered
redirect URI):

```sh
oauth2c "$ISSUER" \
  --grant-type authorization_code \
  --auth-method none \
  --client-id "$CLIENT_ID" \
  --response-types code \
  --response-mode query \
  --scopes openid \
  --pkce \
  --nonce n-0S6_WzA2Mj \
  --redirect-url "$REDIRECT_URI" \
  --callback-addr "$CALLBACK_ADDR" \
  --browser-timeout 10m \
  >"$out/token.json" 2>"$out/trace.jsonl"
```

`$CALLBACK_ADDR` is `host:port` of the listener (e.g. `127.0.0.1:8400`).
It may differ from `--redirect-url` (proxy, `0.0.0.0`). Same host:port
as the redirect is enough when they match.

## Diagnose

Do not parse tokens from stderr. Use stdout (`token.json`).

Read `trace.jsonl` in this order (one JSON object per line):

1. `error` — object: `error`, optional `status`, `error_description`
   (unknown flag, missing args, `Interrupted`, grant failure)
2. any `check <name>` with `result` = `fail` (nonce omitted is fail
   with exit 0; a nonce mismatch is fail with exit 1)
3. the last `request.response` — HTTP `status` plus body
   (`error` / `error_description` on failure; token fields on success)

Then:

- `--<flag> is empty` / `client id is required` → required input missing
- unknown / missing `--grant-type` → use a value from the table
- discovery 404 → strip trailing slash; pass the issuer, not `/authorize`
- `unauthorized_client` / `unsupported_grant_type` on a grant this
  client must not use → **pass**; do not switch clients to make it
  succeed
- `access_token` is `(opaque)` or `(jwe)` → successful token response;
  do not add `--audience` unless a resource-specific token is required
- warning about `code_challenge` → should have used `--pkce` up front
- `check id_token.*` fail → compare `expected` to ID token claims
  (nonce/aud/iss)
- process idle after `authorization_url` or `verification_url` → waiting
  for a human; say so before waiting

## Report

From the temp files, in chat: exit code, expected vs actual, `check *`
results, `iss` / `aud` / `nonce`, and `error` / `error_description`.
Never paste `client_secret`, refresh tokens, or raw JWTs.

## Do not

- Merge stdout and stderr (`2>&1`)
- Write `token.json` / `trace.jsonl` into the repo
- Run against credentials that cannot appear in logs
- Commit `.env.auth0`
- Start `authorization_code`, `implicit`, or device grant unattended
- Pass `--callback-addr` / `--redirect-url` with port `0`

## Reference

Flag enums, stderr keys, provider quirks: [reference.md](reference.md)
Human examples: https://github.com/sukujgrg/oauth2c/blob/master/README.md
