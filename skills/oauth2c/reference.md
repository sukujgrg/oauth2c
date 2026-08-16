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

JSON lines. Parse each line as one object. `--silent` drops the trace.
Stdout is still token JSON.

Keep the streams separate:

```sh
oauth2c "$OAUTH2C_ISSUER" --grant-type client_credentials ... >token.json 2>trace.jsonl
```

If a human wants YAML, they need [yq](https://github.com/mikefarah/yq)
(`brew install yq`): `yq -p json -o yaml <trace.jsonl`.

Each event has one top-level key.

| Key | Meaning |
| --- | --- |
| `request` | HTTP call: `method`, `url`, form/query/headers, nested `response`. `Authorization: Basic …` is redacted; `client_secret` still appears under `input`. |
| `input` | Resolved client config (includes secrets). |
| `check <name>` | Client-side assertion. `result` is `pass`, `fail`, or `skip`. Failed checks exit 1. |
| `access_token` / `id_token` | JWT claims, `(opaque)`, or `(jwe)`. |
| `error` | Failure message. |
| `warning` | Non-fatal hint. |
| `authorization_url` / `verification_url` / `waiting` | Browser or device-flow prompts. The process is waiting for a user. |

SIGINT/SIGTERM prints `Interrupted` and exits 1.

## Auth0 demo env

`./scripts/setup-auth0.sh` writes `.env.auth0` (gitignored). Source it first.

| Variable | Use |
| --- | --- |
| `OAUTH2C_ISSUER` | issuer (no trailing slash) |
| `OAUTH2C_AUDIENCE` | required for Auth0 API access tokens |
| `OAUTH2C_SCOPE` | API scope for client credentials |
| `OAUTH2C_WEB_CLIENT_ID` / `OAUTH2C_WEB_CLIENT_SECRET` | confidential app |
| `OAUTH2C_SPA_CLIENT_ID` | public / implicit |
| `OAUTH2C_DEVICE_CLIENT_ID` | device grant |
| `OAUTH2C_USERNAME` / `OAUTH2C_PASSWORD` | password grant |
