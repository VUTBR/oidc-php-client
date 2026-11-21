# Upgrade from 0.4 to 1.0

Version 1.0 follows OAuth 2.1 and validates more strictly by default. Most applications only need
the changes in **Login flow** below.

## Package and requirements

- The package is now `vutbr/oidc-client` (previously `vutbr-cvis-web/oidc-client`).
- PHP 7.4 – 8.6. Newer PHP versions get `lcobucci/jwt` 5, `phpseclib` 4 and Guzzle 8 automatically.

## Login flow

- **Nonce is required.** Store `getNonce()` before the redirect and call `setNonce()` before
  `getAccessToken('authorization_code', ...)`. Missing nonce throws `LogicException`.
- **PKCE (S256) is always used.** Store `getPkceCode()` before the redirect and call `setPkceCode()`
  before exchanging the code. Missing verifier throws `LogicException`. `pkceMethod` other than `S256`
  throws `InvalidConfigurationException`.
- Validate the redirect back with `validateAuthorizationResponse($_GET, $storedState)`, which checks
  `iss`, `state` and error responses and returns the code.

```php
// before
$token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

// after
$code = $provider->validateAuthorizationResponse($_GET, $_SESSION['oauth2_state']);
$provider->setNonce($_SESSION['oauth2_nonce']);
$provider->setPkceCode($_SESSION['oauth2_pkce']);
$token = $provider->getAccessToken('authorization_code', ['code' => $code]);
```

## Configuration

- Without `issuer` and `publicKey`, discovery of `https://id.vut.cz/auth` is used.
- Default endpoint URLs of `VutProvider` now point to the real endpoints (`https://id.vut.cz/auth/common/oauth2/...`).
- The issuer in the discovery document must exactly match the configured `issuer`.
- `clientSecret` is required (confidential clients only).
- The client authenticates with `client_secret_post` as before; `'tokenEndpointAuthMethod' => 'client_secret_basic'`
  switches to HTTP Basic.

## Token validation

- Only the algorithms in `id_token_signing_alg_values_supported` (or `idTokenSigningAlgValues`, default `RS256`)
  are accepted; `none` is always rejected. HMAC algorithms are verified with the client secret only, never with
  the public keys.
- The `signer` collaborator was removed. To pin one algorithm, use `'idTokenSigningAlgValues' => ['RS256']`.
- ID tokens must contain `iat` and `exp`; `nbf` is checked when present.
- An ID token returned by the `refresh_token` grant is now validated too.
- Logout tokens: `iat`, `exp` and `jti` are required, a `typ` header must be `logout+jwt` when present and the
  key is selected by `kid`. The `events` claim is checked by content: a JSON object per the specification, or a
  JSON-encoded string of it (as sent by id.vut.cz).
- Validation options (`nbfToleranceSeconds`, `maxAge`, `requireAuthTime`, `acrValues`) are no longer sent
  to the token endpoint.

## API changes

- `revokeAccessToken(string $token, ?string $tokenTypeHint = null)`; the revocation request uses the
  configured client authentication method.
- `resource` (RFC 8707) accepts a single URI string.
- `getLogoutUrl()` returns `string`, keeps the port of the end session endpoint and accepts
  `id_token_hint`, `state`, `ui_locales` and `logout_hint`.
- `getLogoutToken()` returns `Lcobucci\JWT\Token\Plain`.
- `getAccessToken()` returns `Flow\IdToken` when the response contains an ID token, otherwise
  `Flow\AccessToken`. Both extend `League\OAuth2\Client\Token\AccessToken` and add `getScopes()`.
- `getIdTokenIssuer()` is public.
- `JWKConverter` and the `RsaPss` signers work with phpseclib 3 and 4 (through the internal `Crypto\Phpseclib`
  bridge). PS256 and PS384 signers were added.
- New exceptions: `AuthorizationErrorException`, `InvalidAuthorizationResponseException`.
