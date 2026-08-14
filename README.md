# OAuth2c

[![status](https://github.com/sukujgrg/oauth2c/workflows/build/badge.svg)](https://github.com/sukujgrg/oauth2c/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/sukujgrg/oauth2c.svg)](https://github.com/sukujgrg/oauth2c/releases)

`oauth2c` is a command-line tool for interacting with OAuth 2.0 authorization
servers. It fetches access tokens using any grant type or client authentication
method, and is compliant with almost all basic and advanced OAuth 2.0, OIDC,
OIDF FAPI and JWT profiles.

This is a fork of [cloudentity/oauth2c](https://github.com/cloudentity/oauth2c),
maintained independently for other use cases. oauth2c was created by Cloudentity;
this fork exists thanks to their work.

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

Clone and install:

```sh
git clone https://github.com/sukujgrg/oauth2c.git
cd oauth2c
make install
```

`make` sets `GOEXPERIMENT=jsonv2` so the experimental `encoding/json/v2` package
is available.

You can also download a pre-built binary from the [releases page].

[releases page]: https://github.com/sukujgrg/oauth2c/releases

## Demo with Auth0

**Prerequisite:** a free Auth0 tenant. Create one at
[manage.auth0.com](https://manage.auth0.com/) (no paid plan is required for the
core examples below).

Then provision the demo apps with the
[Auth0 CLI](https://auth0.com/docs/deploy-monitor/auth0-cli):

```sh
brew install auth0
auth0 login
auth0 tenants use <your-tenant>.us.auth0.com   # or .eu.auth0.com / .au.auth0.com
./scripts/setup-auth0.sh   # or: make auth0-setup
set -a && source .env.auth0 && set +a
```

`scripts/setup-auth0.sh` is idempotent. It creates (or updates) an API, a
confidential web app, an M2M app, a public SPA, a native device app, and a
database user (`oauth2c-demo@example.com` by default, override with `--email`),
then writes client IDs, secrets, and that user's password to `.env.auth0`
(gitignored). Browser login and the password grant use `$OAUTH2C_USERNAME` /
`$OAUTH2C_PASSWORD`.

`go test ./cmd` runs the non-browser grants against this tenant when
`.env.auth0` is present, and skips them otherwise.

Pass the issuer **without a trailing slash**. oauth2c appends
`/.well-known/openid-configuration` to the value you give it.

A free Auth0 tenant covers the core grants in this README. Advanced profiles
(JARM, PAR, RAR, private_key_jwt, mTLS, JWT bearer) need another authorization
server or Auth0 Enterprise / Highly Regulated Identity; see
[Advanced profiles](#advanced-profiles).

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
      --no-browser                                          do not open browser
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
  -s, --silent                                              silent mode
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

`oauth2c` prints all the requests it made to obtain an access token. If you want
to integrate it with CI/CD pipeline use the `--silent` flag.

For more information on the available options and arguments run
`oauth2c --help`.

## Examples

Load `.env.auth0` (written by `./scripts/setup-auth0.sh` or `make auth0-setup`):

```sh
set -a && source .env.auth0 && set +a
```

### Grant types

> **NOTE**: The authorization code, implicit, hybrid and device grant flows
> require browser and user authentication.

#### Authorization code

This grant type involves a two-step process where the user first grants
permission to access their data, and then the client exchanges the authorization
code for an access token. This grant type is typically used in server-side
applications.

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

This grant type is similar to the authorization code grant, but the access token
is returned directly to the client without an intermediate authorization code.
This grant type is typically used in single-page or mobile applications.

> **Note**: The implicit flow is not recommended for use in modern OAuth2
> applications. Instead, it is recommended to use the authorization code flow
> with PKCE (Proof Key for Code Exchange) for added security.

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

To use the OAuth2 hybrid flow to obtain an authorization code and an ID token,
the client first sends an authorization request to the OAuth2 provider. The
request should include the code and id_token response types.

The OAuth2 provider will then return an authorization code and an ID token to
the client, either in the response body or as fragment parameters in the
redirect URL, depending on the response mode specified in the request. The
client can then use the authorization code to obtain an access token by sending
a token request to the OAuth2 provider.

The ID token can be used to verify the identity of the authenticated user, as it
contains information such as the user's name and email address. The ID token is
typically signed by the OAuth2 provider, so the client can verify its
authenticity using the provider's public key.

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

This grant type involves the client providing its own credentials to the OAuth2
server, which then returns an access token. This grant type is typically used
for server-to-server communication, where the client is a trusted server rather
than a user.

Auth0 client-credentials requests need `--audience` set to the API identifier
created by `scripts/setup-auth0.sh`.

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

This grant type involves the client providing a refresh token to the OAuth2
server, which then returns a new access token.

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

This grant type involves the client providing the user's username and password
to the OAuth2 server, which then returns an access token. This grant type should
only be used in secure environments, as it involves sending the user's
credentials to the OAuth2 server.

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

Auth0 device flow uses a public native application, so there is no client
secret.

```sh
oauth2c "$OAUTH2C_ISSUER" \
  --client-id "$OAUTH2C_DEVICE_CLIENT_ID" \
  --grant-type urn:ietf:params:oauth:grant-type:device_code \
  --auth-method none \
  --audience "$OAUTH2C_AUDIENCE" \
  --scopes openid,email,offline_access
```

[Learn more about the device flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow)

JWT bearer and token exchange are implemented by oauth2c but are not part of
the free Auth0 demo. See [Advanced profiles](#advanced-profiles).

### Auth methods

#### Client Secret Basic

This client authentication method involves the client sending its credentials as
part of the HTTP Basic authentication header in the request to the OAuth2
server. This method is simple and widely supported, but it is less secure than
other methods because the client secret is sent in the clear.

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

This client authentication method involves the client sending its credentials as
part of the request body in the request to the OAuth2 server. This method
provides more security than the basic authentication method, but it requires the
request to be sent via HTTPS to prevent the client secret from being
intercepted.

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

`client_secret_jwt`, `private_key_jwt`, and `tls_client_auth` are implemented
by oauth2c. Auth0 advertises the latter two on discovery but they require
Enterprise / Highly Regulated Identity. See
[Advanced profiles](#advanced-profiles).

#### None with PKCE

Public clients, such as mobile apps, are unable to authenticate themselves to
the authorization server in the same way that confidential clients can because
they do not have a client secret. To protect themselves from having their
authorization codes intercepted and used by attackers, public clients can use
PKCE (Proof Key for Code Exchange) during the authorization process. PKCE
provides an additional layer of security by ensuring that the authorization code
can only be exchanged for a token by the same client that initially requested
it. This helps prevent unauthorized access to the token.

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

#### PKCE

The Proof Key for Code Exchange (PKCE) is an extension to the OAuth2
authorization code grant flow that provides additional security when
authenticating with an OAuth2 provider. In the PKCE flow, the client generates a
code verifier and a code challenge, which are then sent to the OAuth2 provider
during the authorization request. The provider returns an authorization code,
which the client then exchanges for an access token along with the code
verifier. The provider verifies the code verifier to ensure that the request is
coming from the same client that initiated the authorization request.

This additional step helps to prevent attackers from intercepting the
authorization code and using it to obtain an access token. PKCE is recommended
for all public clients, such as single-page or mobile applications, where the
client secret cannot be securely stored.

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

#### Nonce

OpenID Connect `nonce` associates a client session with an ID Token and
mitigates replay attacks. Authorization requests still send a generated `nonce`
by default. When `--nonce` is set, oauth2c uses that value instead. If an ID
Token is returned, oauth2c verifies its signature and `iss`, `aud`, `exp`, and
`iat` claims, then fails when the `nonce` claim is missing or does not match.

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

Request objects, JARM, PAR, DPoP, and RAR are implemented by oauth2c but are
not enabled on a free Auth0 tenant. See
[Advanced profiles](#advanced-profiles).

### Miscellaneous

#### Using HTTPs for Callback URL

You can use `--callback-tls-cert` and `--callback-tls-key` flags to specify a
TLS certificate and key for the HTTPs callback redirect URL.

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

If your authorization server does not support OIDC, you can specify the endpoint manually using flags. 

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

oauth2c still implements these flows. They are omitted from
`scripts/setup-auth0.sh` because a free Auth0 tenant does not expose them
(or exposes a different profile than the one oauth2c demos). Use an
authorization server that supports the relevant spec — for example Cloudentity,
Keycloak, or Auth0 Enterprise with the Highly Regulated Identity add-on.

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

DPoP needs an authorization server that advertises it. The sample key in this
repo is PS256. Auth0, when DPoP is enabled on an API, accepts ES256 proofs and
will reject this key.

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
