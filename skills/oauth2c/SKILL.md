---
name: oauth2c
description: >-
  Drive the oauth2c CLI to test OAuth 2.0 / OIDC apps against a real
  authorization server. Use when running grants, fetching tokens, checking
  PKCE/nonce/PAR/DPoP, or diagnosing protocol failures with oauth2c.
---

# oauth2c

Flag-driven OAuth 2.0 / OIDC client. No prompts. Token JSON on stdout.
JSON-lines protocol trace on stderr. Traces dump secrets; not a
production client.

Install (no Go required):

```sh
curl -fsSL https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.ps1 | iex
```

Or download a release from https://github.com/sukujgrg/oauth2c/releases

Copy this directory into the agent's skills path as `oauth2c/` (Cursor,
Claude, Codex, or equivalent).

## Workflow

1. `oauth2c version` — if that fails, install the binary.
2. If using the Auth0 demo, source `.env.auth0` and confirm the vars you
   will pass are non-empty. An empty flag value exits 1.
3. Prefer a grant that does not wait on a browser. Do not start a browser
   grant unless a human can finish login. `--no-browser` only skips opening
   the URL; it still waits.
4. Keep stdout and stderr separate. Do not use `2>&1`.
5. First run: no `--silent`. Exit 0 → token JSON on stdout. Later runs may
   add `--silent` if you only need that JSON.
6. Exit 1 → diagnose from stderr, fix flags, rerun. Do not invent a new client.

```
oauth2c <issuer-url-or-json-file> --grant-type <type> [flags] >token.json 2>trace.jsonl
```

- `--grant-type` is required.
- stderr is JSON lines. Parse each line as one object. Do not parse the
  whole stream as one object. `--silent` drops the trace. Stdout is
  always token JSON.
- Issuer: no trailing slash. oauth2c appends `/.well-known/openid-configuration`.
- First arg may be a JSON file: `client_id`, `client_secret`,
  `openid_discovery_endpoint`. Flags override the file.
- List flags (`--scopes`, `--audience`, `--response-types`) are comma-separated.
- Default `--redirect-url` is `http://localhost:9876/callback` (must be
  registered on the client).
- Timeouts: `--http-timeout 1m`, `--browser-timeout 10m`. Browser grants block
  until callback or that timeout.

## Grants

| `--grant-type` | Human? | Typical extra flags |
| --- | --- | --- |
| `client_credentials` | no | `--client-id --client-secret --auth-method --audience` |
| `password` | no | `--client-id --client-secret --auth-method --username --password` |
| `refresh_token` | no | `--client-id --client-secret --auth-method --refresh-token` |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | no | `--client-id --client-secret --auth-method --assertion --signing-key` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | no | `--client-id --client-secret --auth-method --subject-token --subject-token-type` |
| `authorization_code` | yes | `--client-id --client-secret --auth-method --response-types code --response-mode query` |
| `implicit` | yes | `--client-id --auth-method none --response-types token` or `id_token` |
| `urn:ietf:params:oauth:grant-type:device_code` | yes | `--client-id --auth-method none` |

Hybrid: `--grant-type authorization_code --response-types code,id_token`.

Default first probe (Auth0 demo env sourced):

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes "$OAUTH2C_SCOPE" \
  >token.json 2>trace.jsonl
```

## Diagnose

Do not parse tokens from stderr. Use stdout (`token.json`).

On failure, read `trace.jsonl` in this order (one JSON object per line):

1. `error`
2. any `check <name>` with `result` = `fail`
3. the last `request.response`

Then apply the matching fix:

- `--<flag> is empty` / `client id is required` → env var unset or
  required flag omitted; source `.env.auth0` and rerun
- unknown / missing `--grant-type` → use a value from the table above
- discovery 404 → strip trailing slash; pass the issuer, not `/authorize`
- Auth0 token opaque or unusable → add `--audience`
- warning about `code_challenge` → rerun with `--pkce`
- `check id_token.*` fail → compare `input` to ID token claims (nonce/aud/iss)
- process idle after `authorization_url` or `verification_url` → waiting for a
  human (callback or device approval); `--no-browser` does not skip that wait

## Do not

- Merge stdout and stderr (`2>&1`)
- Run against credentials that cannot appear in logs
- Commit `.env.auth0`
- Start `authorization_code`, `implicit`, or `device_code` unattended

## Reference

Flag enums, stderr keys, and Auth0 env: [reference.md](reference.md)
Human examples: https://github.com/sukujgrg/oauth2c/blob/master/README.md
