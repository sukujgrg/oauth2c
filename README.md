# OAuth2c

[![status](https://github.com/sukujgrg/oauth2c/workflows/build/badge.svg)](https://github.com/sukujgrg/oauth2c/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/sukujgrg/oauth2c.svg)](https://github.com/sukujgrg/oauth2c/releases)

`oauth2c` is a flag-driven OAuth 2.0 / OpenID Connect client for testing
OAuth apps. There are no interactive prompts: every grant is configured
from flags. LLM agents and scripts can drive a real authorization server,
read token JSON on stdout, and read a JSON-lines protocol trace on
stderr: what was sent, what came back, which checks passed or failed,
and what the tokens contain. If you want YAML, install
[yq](https://github.com/mikefarah/yq) (`brew install yq`) and pipe
stderr through `yq -p json -o yaml`.

Printing raw tokens, client secrets, JWTs, and request parameters is
intentional so a model (or a human) can diagnose the grant. This is not a
production client. Do not point it at credentials you cannot afford to
leak into a log.

`--silent` discards the protocol trace so callers get only the token
JSON on stdout. `error` events still appear if the command fails.

Browser grants (authorization code, hybrid, implicit, device) still need a
user at the authorization server. `--no-browser` only skips opening the
URL; the process still waits for the callback or device approval. Client
credentials, password, refresh token, JWT bearer, and token exchange do
not wait on a user.

Agents: install [skills/oauth2c](skills/oauth2c/SKILL.md) as a skill
(copy that directory into the agent's skills path).

## Difference from cloudentity/oauth2c

This is a fork of [cloudentity/oauth2c](https://github.com/cloudentity/oauth2c).
Cloudentity built the original; this repo is a near-total rewrite.

**cloudentity/oauth2c** is a user-friendly client for fetching access tokens
(interactive prompts, TUI, Homebrew). **This fork** drops the TUI so an LLM
or script can drive every grant from flags and parse a JSON-lines trace of
the protocol. Demos use an Auth0 tenant you control.

Grant types and client authentication methods are the same. The Go module and
version line are new (`github.com/sukujgrg/oauth2c` `v1.0.0`), not a
continuation of upstream `v1.20.x`.

## Features

- support for **authorization code**, **hybrid**, **implicit**, **password**,
  **client credentials**, **refresh token**, **JWT bearer**, **token exchange**,
  **device** grant flows
- support for **client secret basic**, **client secret post**, **client secret
  JWT**, **private key JWT**, **TLS client auth** client authentication methods
- passing request parameters as plaintext, signed, and/or encrypted JWT
- support for **Proof Key for Code Exchange** (**PKCE**)
- support for OpenID Connect **nonce**
- support for **JWT Secured Authorization Response Mode** (**JARM**)
- support for **Pushed Authorization Requests** (**PAR**)
- support for **Demonstration of Proof of Possession** (**DPoP**)
- support for **Rich Authorization Requests** (**RAR**)

## Installation

Go is not required. The installer picks the binary for your machine.

macOS / Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/sukujgrg/oauth2c/master/scripts/install.ps1 | iex
```

Pin a version with `OAUTH2C_VERSION=v2.0.1`. Change the install directory
with `OAUTH2C_BINDIR`.

Or download a binary from the [releases page].

[releases page]: https://github.com/sukujgrg/oauth2c/releases

From source (needs Go):

```sh
git clone https://github.com/sukujgrg/oauth2c.git
cd oauth2c
make install
```

`make` sets `GOEXPERIMENT=jsonv2` so the experimental `encoding/json/v2` package
is available, and stamps `oauth2c version` from the current git tag.

```sh
GOEXPERIMENT=jsonv2 go install github.com/sukujgrg/oauth2c@v2.0.1
```

## Demo with Auth0

**Prerequisite:** a free Auth0 tenant. Create one at
[manage.auth0.com](https://manage.auth0.com/) (no paid plan is required for the
core examples below).

Then provision the demo apps with the
[Auth0 CLI](https://auth0.com/docs/deploy-monitor/auth0-cli)
(`brew install auth0` or the installer for your OS):

```sh
auth0 login
auth0 tenants use <your-tenant>.us.auth0.com   # or .eu.auth0.com / .au.auth0.com
./scripts/setup-auth0.sh
set -a && source .env.auth0 && set +a
```

`scripts/setup-auth0.sh` is idempotent. It creates (or updates) an API, a
confidential web app, an M2M app, a public SPA, a native device app, and a
database user (`oauth2c-demo@example.com` by default, override with `--email`),
then writes client IDs, secrets, and that user's password to `.env.auth0`
(gitignored). Browser login and the password grant use `$OAUTH2C_USERNAME` /
`$OAUTH2C_PASSWORD`.

Pass the issuer **without a trailing slash**. oauth2c appends
`/.well-known/openid-configuration` to the value you give it.

A free Auth0 tenant covers the core grants in this README. Flows that need
another authorization server are in [Advanced profiles](#advanced-profiles).

## Usage

```sh
oauth2c [issuer url] [flags]
```

`--grant-type` is required. The available flags are:

```sh
      --acr-values strings                                  ACR values
      --actor-token string                                  acting party token
      --actor-token-type string                             acting party token type
      --assertion string                                    claims for jwt bearer assertion
      --audience strings                                    requested audience
      --auth-method string                                  token endpoint authentication method
      --authentication-code string                          authentication code used for passwordless authentication
      --authorization-endpoint string                       server's authorization endpoint
      --browser-timeout duration                            browser timeout (default 10m0s)
      --callback-addr string                                callback server bind address (e.g., 0.0.0.0:8080)
      --callback-tls-cert string                            path to callback tls cert pem file
      --callback-tls-key string                             path to callback tls key pem file
      --claims string                                       use claims
      --client-id string                                    client identifier
      --client-secret string                                client secret
      --device-authorization-endpoint string                server's device authorization endpoint
      --dpop                                                use DPoP
      --encrypted-request-object                            pass request parameters as encrypted jwt
      --encryption-key string                               path or url to encryption key in jwks format
      --grant-type string                                   grant type
  -h, --help                                                help for oauth2c
      --http-timeout duration                               http client timeout (default 1m0s)
      --id-token-hint string                                id token hint
      --idp-hint string                                     identity provider hint
      --insecure                                            allow insecure connections
      --login-hint string                                   user identifier hint
      --max-age string                                      maximum authentication age in seconds
      --mtls-pushed-authorization-request-endpoint string   server's mtls pushed authorization request endpoint
      --mtls-token-endpoint string                          server's mtls token endpoint
      --no-browser                                          do not open a browser; still waits for the callback or device approval
      --nonce string                                        openid connect nonce
      --par                                                 enable pushed authorization requests (PAR)
      --password string                                     resource owner password credentials grant flow password
      --pkce                                                enable proof key for code exchange (PKCE)
      --prompt strings                                      end-user authorization purpose
      --purpose string                                      string describing the purpose for obtaining End-User authorization
      --pushed-authorization-request-endpoint string        server's pushed authorization request endpoint
      --rar string                                          use rich authorization request (RAR)
      --redirect-url string                                 client redirect url (default "http://localhost:9876/callback")
      --refresh-token string                                refresh token
      --request-object                                      pass request parameters as jwt
      --resource strings                                    requested resource
      --response-mode string                                response mode
      --response-types strings                              response type
      --scopes strings                                      requested scopes
      --signing-key string                                  path or url to signing key in jwks format
  -s, --silent                                              print only the token JSON on stdout
      --subject-token string                                third party token
      --subject-token-type string                           third party token type
      --tls-cert string                                     path to tls cert pem file
      --tls-key string                                      path to tls key pem file
      --tls-root-ca string                                  path to tls root ca pem file
      --token-endpoint string                               server's token endpoint
      --username string                                     resource owner password credentials grant flow username
```

`oauth2c` opens a browser for flows such as authorization code and starts an
HTTP server which acts as a client application and waits for a callback.

> **Note**: To make browser flows work add `http://localhost:9876/callback` as a
> redirect URL to your client.

stderr is JSON lines (one object per event): the protocol trace
(requests, responses, decoded tokens, checks) and CLI failures
(unknown flags, missing args, interrupt). `--help` stays human text on
stdout. Use `--silent` when you only want the token JSON on stdout;
`error` events still appear if the command fails. If you want YAML,
install [yq](https://github.com/mikefarah/yq) (`brew install yq`) and
pipe stderr through `yq -p json -o yaml`.

## Examples

Load `.env.auth0` (written by `./scripts/setup-auth0.sh`):

```sh
set -a && source .env.auth0 && set +a
```

Auth0 access tokens for the demo API need `--audience "$OAUTH2C_AUDIENCE"`.

### Grant types

> **NOTE**: The authorization code, implicit, hybrid and device grant flows
> require browser and user authentication.

#### Authorization code

The client receives an authorization code in the browser callback and exchanges
it for tokens. Typical for confidential server-side apps.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access
```

[Learn more about authorization code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)

#### Implicit

Tokens are returned to the browser without a code exchange. Prefer authorization
code with PKCE for new apps.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_SPA_CLIENT_ID" \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email
```

[Learn more about implicit flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post)

#### Hybrid

The authorization response includes both a code and an ID token
(`response_types code,id_token`).

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --response-types code,id_token \
  --response-mode form_post \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access
```

[Learn more about the hybrid flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/hybrid-flow)

#### Client credentials

The client authenticates as itself and receives an access token. Used for
server-to-server calls.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes "$OAUTH2C_SCOPE"
```

[Learn more about the client credentials flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow)

#### Refresh token

Exchange a refresh token for a new access token.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --grant-type refresh_token \
  --auth-method client_secret_basic \
  --refresh-token "$REFRESH_TOKEN"
```

> **Note** In order to use this command, you must first set the REFRESH_TOKEN
> environment variable
>
> <details>
> <summary>Show example</summary>
>
> ```sh
> export REFRESH_TOKEN=`oauth2c "$OAUTH2C_ISSUER" \
>   --client-id "$OAUTH2C_WEB_CLIENT_ID" \
>   --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
>   --response-types code \
>   --response-mode query \
>   --grant-type authorization_code \
>   --auth-method client_secret_basic \
>   --audience "$OAUTH2C_AUDIENCE" \
>   --scopes openid,email,offline_access \
>   --silent | jq -r .refresh_token`
> ```
>
> </details>

[Learn more about the refresh token flow](https://auth0.com/docs/secure/tokens/refresh-tokens/use-refresh-tokens)

#### Password

The client sends the resource owner's username and password to the token
endpoint.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --grant-type password \
  --username "$OAUTH2C_USERNAME" \
  --password "$OAUTH2C_PASSWORD" \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid
```

[Learn more about the password flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow)

#### Device

The device authorization grant is for clients that cannot host a browser, such
as a TV or CLI. oauth2c asks the authorization server for a device code, prints
a verification URL and user code, then polls the token endpoint until the user
approves the request in a browser on another device.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_DEVICE_CLIENT_ID" \
  --grant-type urn:ietf:params:oauth:grant-type:device_code \
  --auth-method none \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access
```

[Learn more about the device flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow)

### Auth methods

#### Client Secret Basic

The client authenticates with an HTTP Basic `Authorization` header.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes "$OAUTH2C_SCOPE"
```

[Learn more about client secret basic](https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-client-credentials-flow)

#### Client Secret Post

The client sends `client_id` and `client_secret` in the token request body.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_POST_CLIENT_ID" \
  --client-secret "$OAUTH2C_POST_CLIENT_SECRET" \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes "$OAUTH2C_SCOPE"
```

[Learn more about client secret post](https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-client-credentials-flow)

#### None with PKCE

Public clients have no secret. PKCE binds the authorization code to the client
that started the request.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_SPA_CLIENT_ID" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method none \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email \
  --pkce
```

[Learn more about authorization code flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce)

### Extensions

#### Nonce

OpenID Connect `nonce` associates a client session with an ID Token and
mitigates replay attacks. Authorization requests still send a generated `nonce`
by default. When `--nonce` is set, oauth2c uses that value instead. If an ID
Token is returned, oauth2c verifies its signature and `iss`, `aud`, `exp`, and
`iat` claims. A missing `nonce` claim is logged as a failed check but the
process still succeeds; a mismatched `nonce` exits 1.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_SPA_CLIENT_ID" \
  --grant-type authorization_code \
  --auth-method none \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid \
  --pkce \
  --nonce n-0S6_WzA2Mj
```

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_SPA_CLIENT_ID" \
  --grant-type implicit \
  --response-types id_token \
  --response-mode form_post \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid \
  --nonce n-0S6_WzA2Mj
```

### Miscellaneous

#### Using HTTPS for Callback URL

You can use `--callback-tls-cert` and `--callback-tls-key` flags to specify a
TLS certificate and key for the HTTPS callback redirect URL.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access \
  --redirect-url https://localhost:9876/callback \
  --callback-tls-cert https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/cert.pem \
  --callback-tls-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/key.pem
```

#### Using a TLS-Terminating Proxy

When running behind a TLS-terminating proxy (e.g., nginx, Traefik, or a cloud
load balancer), use `--callback-addr` to specify the local bind address while
keeping the public HTTPS URL in `--redirect-url`.

`scripts/setup-auth0.sh` only registers the localhost callbacks. Add the public
URL to the Auth0 application's Allowed Callback URLs before running this.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access \
  --redirect-url https://example.com/callback \
  --callback-addr 0.0.0.0:8080
```

In this configuration:
- `--redirect-url` is the public URL sent to the IdP in the OAuth request
- `--callback-addr` is the local address where the callback server binds
- The callback server serves HTTP (no TLS certs provided), while the proxy handles TLS termination

#### Specifying Authorization Server's Endpoint Manually

If discovery is unavailable, set the endpoints with flags.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_WEB_CLIENT_ID" \
  --client-secret "$OAUTH2C_WEB_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access \
  --token-endpoint "$OAUTH2C_ISSUER/oauth/token" \
  --authorization-endpoint "$OAUTH2C_ISSUER/authorize"
```

## Advanced profiles

These flows are implemented by oauth2c but are not part of the Auth0 demo.
Use an authorization server that supports the relevant spec.

Replace `$AS_ISSUER` / `$AS_CLIENT_ID` / `$AS_CLIENT_SECRET` with values from
that server.

#### JWT Bearer

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --grant-type urn:ietf:params:oauth:grant-type:jwt-bearer \
  --auth-method client_secret_basic \
  --scopes email \
  --signing-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/rsa/key.json \
  --assertion '{"sub":"jdoe@example.com"}'
```

#### Token exchange

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --grant-type urn:ietf:params:oauth:grant-type:token-exchange \
  --auth-method client_secret_basic \
  --scopes email \
  --subject-token "$SUBJECT_TOKEN" \
  --subject-token-type urn:ietf:params:oauth:token-type:access_token \
  --actor-token "$ACTOR_TOKEN" \
  --actor-token-type urn:ietf:params:oauth:token-type:access_token
```

#### Client Secret JWT

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --grant-type client_credentials \
  --auth-method client_secret_jwt \
  --scopes email
```

#### Private Key JWT

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --signing-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/rsa/key.json \
  --grant-type client_credentials \
  --auth-method private_key_jwt
```

#### TLS Client Auth

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --tls-cert https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/cert.pem \
  --tls-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/key.pem \
  --grant-type client_credentials \
  --auth-method tls_client_auth
```

#### Request Object

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --request-object
```

#### Request claims

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,offline_access \
  --claims '{"id_token":{"email": {"essential": true}}}'
```

#### JARM

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_post \
  --scopes openid,email,offline_access \
  --encryption-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/rsa/key.json
```

#### PAR

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --par
```

#### DPoP

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --signing-key https://raw.githubusercontent.com/sukujgrg/oauth2c/master/data/ps/key.json \
  --dpop
```

#### RAR

```sh
oauth2c "$AS_ISSUER" \
  --client-id "$AS_CLIENT_ID" \
  --client-secret "$AS_CLIENT_SECRET" \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --rar '[{"type":"payment_initiation","locations":["https://example.com/payments"],"instructedAmount":{"currency":"EUR","amount":"123.50"},"creditorName":"Merchant A","creditorAccount":{"bic":"ABCIDEFFXXX","iban":"DE02100100109307118603"},"remittanceInformationUnstructured":"Ref Number Merchant"}]'
```

## License

`oauth2c` is released under the
[Apache v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Contributing

We welcome contributions! If you have an idea for a new feature or have found a
bug, please open an issue on GitHub.

`go test ./cmd` runs the non-browser grants against `.env.auth0` when that file
is present, and skips them otherwise.
