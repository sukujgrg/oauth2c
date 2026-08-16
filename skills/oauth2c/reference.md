# oauth2c reference

Read this when the grant, auth method, or stderr key is not in SKILL.md.

## Auth methods

`--auth-method`: `client_secret_basic`, `client_secret_post`,
`client_secret_jwt`, `private_key_jwt`, `tls_client_auth`,
`self_signed_tls_client_auth`, `none`.

`--response-types`: `code`, `id_token`, `token`, `none`.
`--response-mode`: `query`, `form_post`, `query.jwt`, `form_post.jwt`, `jwt`.
`--subject-token-type` / `--actor-token-type`:
`urn:ietf:params:oauth:token-type:access_token`.

Toggles: `--pkce`, `--nonce <value>`, `--par`, `--dpop`, `--insecure`.
`--assertion`, `--claims`, `--rar` must be JSON strings.

## stderr trace

JSON lines. Parse each line as one object. `--silent` drops the
protocol trace; `error` events still appear. Stdout is still token
JSON. `--help` is human text on stdout.

Keep the streams separate. Write files under a 0700 temp dir.

Each event has one top-level key.

| Key | Meaning |
| --- | --- |
| `request` | HTTP call: `method`, `url`, form/query/headers, nested `response`. `Authorization: Basic …` is redacted; `client_secret` still appears under `input`. |
| `request.response` | HTTP result for that call: `status` plus the parsed body. Failure body: `error`, `error_description` (optional `error_hint`, `cause`). Success body: token or discovery fields. There is no `status` anywhere else on `request`. |
| `input` | Resolved client config (includes secrets). |
| `check <name>` | Client-side assertion. `result` is `pass`, `fail`, or `skip`. Failed checks exit 1, except `id_token.nonce` when the authorization server omits a sent nonce (`result: fail`, process continues). A nonce mismatch still exits 1. |
| `access_token` / `id_token` | JWT claims, `(opaque)`, or `(jwe)`. Quote `iss` / `aud` / `nonce` in chat; never the raw JWT. |
| `error` | Object: `error` (code or CLI message), optional `status`, `error_description`. Unknown flags, missing args, SIGINT/SIGTERM (`Interrupted`), grant failure. |
| `warning` | Non-fatal hint. |
| `authorization_url` / `verification_url` / `waiting` | Browser or device-flow prompts. The process is waiting for a user. |

Failed client-credentials example:

```json
{"request":{"method":"POST","url":"https://example.com/oauth/token","grant_type":"client_credentials","response":{"status":401,"error":"unauthorized_client","error_description":"Grant type not allowed"}}}
{"error":{"status":401,"error":"unauthorized_client","error_description":"Grant type not allowed"}}
```

CLI failure (no HTTP status):

```json
{"error":{"error":"client id is required"}}
```

If a human wants YAML, they need [yq](https://github.com/mikefarah/yq)
(`brew install yq`): `yq -p json -o yaml <trace.jsonl`.

## Provider quirks

**Auth0.** Registered redirect URIs are exact, including scheme, host,
path, and port. `http://localhost:8400/callback` is not
`http://127.0.0.1:8400/callback`. `--audience` requests an access token
for that API; omitting it often yields a JWE or opaque access token
usable at `/userinfo`.

**Google Desktop.** Loopback is RFC 8252: any port on `http://127.0.0.1`
or `http://[::1]`. The `redirect_uri` in authorize and token must still
include the port the app actually bound. oauth2c does not bind `:0` and
rewrite `redirect_uri`; use a fixed port. To see any-port policy, run
two fixed ports. Google issues a `client_secret` for Desktop apps; send
it on the token request with `--auth-method client_secret_post`. PKCE
does not replace that. Do not use the skill’s public recipe
(`--auth-method none`). Google Web clients are exact-match, like Auth0.

## Auth0 demo env

`./scripts/setup-auth0.sh` writes `.env.auth0` (gitignored). Optional.
User-supplied issuer, `client_id`, and redirect are the default path.

| Variable | Use |
| --- | --- |
| `OAUTH2C_ISSUER` | issuer (no trailing slash) |
| `OAUTH2C_AUDIENCE` | API access tokens only |
| `OAUTH2C_SCOPE` | API scope for client credentials |
| `OAUTH2C_WEB_CLIENT_ID` / `OAUTH2C_WEB_CLIENT_SECRET` | confidential app |
| `OAUTH2C_SPA_CLIENT_ID` | public / implicit |
| `OAUTH2C_DEVICE_CLIENT_ID` | device grant |
| `OAUTH2C_USERNAME` / `OAUTH2C_PASSWORD` | password grant |
