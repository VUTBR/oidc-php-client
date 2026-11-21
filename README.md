# OAuth 2.1 / OpenID Connect Client for id.vut.cz

OpenID Connect client for the VUT identity provider ([id.vut.cz](https://id.vut.cz/auth/.well-known/openid-configuration)),
built on [league/oauth2-client](https://github.com/thephpleague/oauth2-client) and [lcobucci/jwt](https://github.com/lcobucci/jwt).

It is intended for PHP back-end applications, i.e. **confidential clients** with a `client_secret`.

- Authorization code flow with mandatory **PKCE (S256)** and **nonce**
- **Client credentials** grant for server-to-server access tokens
- Full ID token validation: signature (algorithm allow-list, keys from JWKS selected by `kid`), `iss`, `aud`, `azp`, `exp`/`iat`/`nbf`, `nonce`, optionally `acr` and `auth_time`/`max_age`
- Authorization response validation: `state` and `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)), error responses
- Client authentication with `client_secret_basic` (default) or `client_secret_post`
- Refresh tokens (with rotation), token revocation ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)), resource indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707))
- RP-initiated logout and [back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- Discovery with optional PSR-6 cache
- Guzzle or any **PSR-18** HTTP client (e.g. Symfony HttpClient)

## Requirements

* PHP 7.4 – 8.6
* `ext-json`, `ext-openssl`

Composer installs the newest dependency versions your PHP supports: `lcobucci/jwt` 4.3 or 5.x, `phpseclib` 3 or 4,
Guzzle 7 or 8.

## Install

```bash
composer require vutbr/oidc-client
```

Upgrading from 0.x? See [UPGRADE.md](UPGRADE.md).

## Usage

### Configuration

```php
<?php
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

$provider = new VutOpenIDConnectProvider(
	[
		'clientId' => 'your client id',
		'clientSecret' => 'your client secret',
		'redirectUri' => 'https://app.example/callback',
		'scopes' => ['openid', 'profile', 'email'],
		// optional, this is the default - all endpoints and keys are loaded from
		// https://id.vut.cz/auth/.well-known/openid-configuration
		'issuer' => 'https://id.vut.cz/auth',
	],
	[
		// optional PSR-6 cache for the discovery document and the JWKS (1 hour)
		'cache' => $cache,
	],
);
```

| Option | Default | Description |
|---|---|---|
| `clientId`, `clientSecret`, `redirectUri` | – | Client registration (required) |
| `scopes` | `[]` | `openid` is always added |
| `issuer` | `https://id.vut.cz/auth` | OpenID Provider, configured via discovery |
| `tokenEndpointAuthMethod` | `client_secret_basic` | Or `client_secret_post`; when not set, chosen from the discovery document |
| `idTokenSigningAlgValues` | from discovery, else `['RS256']` | Allowed ID token / logout token algorithms |
| `validateAudience` | `true` | Check that `aud` contains the `client_id` |
| `authorizationResponseIssParameterSupported` | from discovery | Require `iss` in the authorization response |
| `publicKey` + `idTokenIssuer` | – | Manual configuration without discovery (PEM or `file://` path(s)) |

| Collaborator | Description |
|---|---|
| `httpClient` | `GuzzleHttp\ClientInterface` or any `Psr\Http\Client\ClientInterface` |
| `cache` | `Psr\Cache\CacheItemPoolInterface` for discovery and JWKS |
| `signer` | `Lcobucci\JWT\Signer`, pins the expected algorithm |
| `clock` | Clock with `now(): DateTimeImmutable` (`lcobucci/clock` or PSR-20), useful in tests |

### Login (authorization code flow)

```php
<?php
use Vut2\Component\OpenIDConnectClient\Exception\AuthorizationErrorException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidAuthorizationResponseException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;

// 1) Redirect the user to id.vut.cz and remember state, nonce, the PKCE verifier and acr_values/max_age
if (!isset($_GET['code']) && !isset($_GET['error'])) {
	$url = $provider->getAuthorizationUrl();
	$_SESSION['oauth2_state'] = $provider->getState();
	$_SESSION['oauth2_nonce'] = $provider->getNonce();
	$_SESSION['oauth2_pkce'] = $provider->getPkceCode();
	$_SESSION['oauth2_requirements'] = $provider->getAuthorizationRequirements();

	header('Location: ' . $url);
	exit;
}

// 2) Validate the redirect back (iss, state, error) and exchange the code; the stored values are single-use
$state = $_SESSION['oauth2_state'] ?? '';
$nonce = $_SESSION['oauth2_nonce'] ?? null;
$pkce = $_SESSION['oauth2_pkce'] ?? null;
$requirements = $_SESSION['oauth2_requirements'] ?? [];
unset($_SESSION['oauth2_state'], $_SESSION['oauth2_nonce'], $_SESSION['oauth2_pkce'], $_SESSION['oauth2_requirements']);

try {
	$code = $provider->validateAuthorizationResponse($_GET, $state);

	$provider->setNonce($nonce);
	$provider->setPkceCode($pkce);
	$provider->setAuthorizationRequirements($requirements);
	$token = $provider->getAccessToken('authorization_code', [
		'code' => $code,
		// tolerated clock skew between id.vut.cz and your server, in seconds
		'nbfToleranceSeconds' => 30,
	]);
} catch (AuthorizationErrorException $e) {
	// the user denied access, or the server returned login_required, unmet_authentication_requirements, ...
	showLoginError($e->getError());
	exit;
} catch (InvalidAuthorizationResponseException | InvalidTokenException $e) {
	// state/iss mismatch or an invalid ID token - never trust such a response
	http_response_code(400);
	exit;
}
session_regenerate_id(true);

// 3) Use the tokens
$accessToken  = $token->getToken();
$refreshToken = $token->getRefreshToken();
$expires      = $token->getExpires();
$scopes       = $token->getScopes();          // granted scopes
$idToken      = $token->getIdToken();         // Lcobucci\JWT\Token\Plain, already validated
$email        = $idToken->claims()->get('email');
$user         = $provider->getResourceOwner($token); // VutUser built from the ID token claims
```

`getAccessToken()` throws a `LogicException` when the nonce or the PKCE verifier was not restored. This is a
programming error, not a user error.

### Token response

`getAccessToken()` returns a `Flow\AccessToken` (or `Flow\IdToken`), a league `AccessToken` with two helpers
for the fields sent by id.vut.cz. The raw response fields stay available in `getValues()`.

```php
$scopes = $token->getScopes();                      // 'scope' (or legacy 'scopes') as an array
if (in_array('trustedDevice', $scopes, true)) {
	// ...
}

$token->getExpires();                               // access token expiration (league)
$token->getRefreshTokenExpires();                   // refresh token expiration from refresh_expires_in, or null
```

Per RFC 6749 §5.1 a missing or empty scope means the granted scope is identical to the requested one;
`getScopes()` returns `[]` in that case.

Tokens can be stored with `json_encode($token)` and restored with `new AccessToken(json_decode($json, true))`
(`new IdToken(...)` for a token with an ID token), including both expirations.

### Client credentials (server-to-server)

For access tokens without a user (cron jobs, service-to-service calls) use the `client_credentials` grant.
`VutProvider` is enough here: it uses the id.vut.cz endpoints directly, sends no discovery request and there is
no nonce, PKCE or ID token involved.

```php
<?php
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Vut2\Component\OpenIDConnectClient\Provider\VutProvider;

$provider = new VutProvider([
	'clientId' => 'your client id',
	'clientSecret' => 'your client secret',
	// 'tokenEndpointAuthMethod' => 'client_secret_post', // default: client_secret_basic
]);

try {
	$token = $provider->getAccessToken('client_credentials', [
		'scope' => ['thiefReadonly', 'userGroups'], // sent space-separated
		'resource' => 'https://api.example/',       // optional (RFC 8707), string or array
	]);
} catch (IdentityProviderException $e) {
	// invalid_client (wrong credentials), invalid_scope (scope not allowed for the client), ...
	throw $e;
}

$accessToken = $token->getToken();
$expires     = $token->getExpires();   // Unix timestamp
$scopes      = $token->getScopes();    // scopes actually granted

// Call the API with "Authorization: Bearer <token>"
$request  = $provider->getAuthenticatedRequest('GET', 'https://api.example/resource', $token);
$response = $provider->getResponse($request);
```

There is no refresh token in this grant. Reuse the access token until it expires and then request a new one,
e.g. with a PSR-6 cache:

```php
$item = $cache->getItem('vut-client-credentials-token');
if (!$item->isHit()) {
	$token = $provider->getAccessToken('client_credentials', ['scope' => ['thiefReadonly']]);
	$item->set($token->jsonSerialize());
	$expires = $token->getExpires() ?? time() + 300;
	$item->expiresAt((new DateTimeImmutable())->setTimestamp($expires - 60)); // renew 1 min early
	$cache->save($item);
}
$token = new \Vut2\Component\OpenIDConnectClient\Flow\AccessToken($item->get());
```

`VutOpenIDConnectProvider` supports the grant as well, which is useful when one application does both user
login and server-to-server calls. It loads the discovery document in its constructor, so pass a `cache`
collaborator to avoid fetching it on every request. A runnable example is in
[`examples/client-credentials.php`](examples/client-credentials.php).

### Authentication requirements (`acr_values`, `max_age`)

```php
$url = $provider->getAuthorizationUrl([
	'acr_values' => ['urn:mfa', 'urn:mfa:passwordless'], // see acr_values_supported in the discovery
	'max_age' => 3600,                                    // re-authenticate if the login is older
	'prompt' => 'login',
]);

$_SESSION['oauth2_requirements'] = $provider->getAuthorizationRequirements();

// after the redirect back: the acr claim must be one of acr_values, auth_time must be within max_age
$provider->setAuthorizationRequirements($_SESSION['oauth2_requirements'] ?? []);
$token = $provider->getAccessToken('authorization_code', ['code' => $code]);
```

The user can remove `acr_values` / `max_age` from the authorization URL, so always restore the stored
requirements (or pass the `acrValues` / `maxAge` options explicitly, which override them). Otherwise requesting
MFA gives no protection.

When id.vut.cz cannot satisfy the requested `acr_values`, `validateAuthorizationResponse()` throws an
`AuthorizationErrorException` with `isUnmetAuthenticationRequirements() === true`.

### Resource indicators

```php
$url = $provider->getAuthorizationUrl(['resource' => 'https://api.example/']);
$token = $provider->getAccessToken('authorization_code', ['code' => $code, 'resource' => 'https://api.example/']);
```

Multiple resources can be passed as an array; they are sent as repeated `resource` parameters.

### Refresh token and token revocation

```php
$newToken = $provider->getAccessToken('refresh_token', ['refresh_token' => $token->getRefreshToken()]);

// refresh tokens are rotated - always store the newest one
$refreshToken = $newToken->getRefreshToken() ?? $token->getRefreshToken();

$provider->revokeAccessToken($newToken->getToken(), 'access_token');
$provider->revokeAccessToken($refreshToken, 'refresh_token');
```

If the refresh response contains an ID token, it is validated (signature, `iss`, `aud`, time claims) and an
`IdToken` is returned. It is not compared with the ID token from the login. Keep the user identity from the
login, or, if you use the claims of the refreshed ID token, check OIDC Core §12.2 yourself:

```php
$new = $newToken instanceof IdToken ? $newToken->getIdToken() : null;
if ($new !== null && $new->claims()->get('sub') !== $_SESSION['user']['sub']) {
	// different user: end the session
}
```

### Logout (RP-initiated)

```php
$url = $provider->getLogoutUrl([
	'id_token_hint' => $idToken,  // string or the token object
	'post_logout_redirect_uri' => 'https://app.example/logged-out',
	'state' => $logoutState,
]);
header('Location: ' . $url);
```

### Back-channel logout

When the user logs out at id.vut.cz, the server sends a signed `logout_token` to the back-channel logout URI
registered for your client. The request comes from the server, not from the user's browser, so the application
must find and end the user's local sessions itself. Store the `sid` (and `sub`) from the ID token at login:

```php
// at login, after getAccessToken()
$claims = $token->getIdToken()->claims();
$sessionStore->register(session_id(), $claims->get('sub'), $claims->get('sid'));
```

The back-channel logout endpoint:

```php
<?php
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;

header('Cache-Control: no-store');

$logoutToken = $_POST['logout_token'] ?? null;
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !is_string($logoutToken) || $logoutToken === '') {
	http_response_code(400);
	exit;
}

try {
	// signature, iss, aud, iat/exp, jti, sub or sid, the back-channel logout event, no nonce
	$token = $provider->getLogoutToken($logoutToken, ['nbfToleranceSeconds' => 30]);
} catch (InvalidTokenException $e) {
	http_response_code(400);
	exit;
}

$sid = $token->claims()->get('sid'); // logs out one OP session
$sub = $token->claims()->get('sub'); // without sid: all sessions of the user

foreach ($sessionStore->pullSessions($sub, $sid) as $phpSessionId) {
	session_id($phpSessionId);
	session_start();
	session_destroy();
}

http_response_code(200);
```

A token without `exp` is rejected when its `iat` is older than `maxLogoutTokenAge` (option, default 120 s).
The library does not detect replays: the endpoint MUST reject a repeated `iss` + `jti`, stored atomically
(e.g. a DB unique key or Redis `SET NX` with TTL) until `exp`, or until `iat` + `maxLogoutTokenAge` when the
token has no `exp`. A complete example is in
[`examples/backchannel-logout.php`](examples/backchannel-logout.php).

### HTTP client

Guzzle is used by default. Any PSR-18 client can be passed as `httpClient`, for example Symfony HttpClient
(the library itself does not depend on Symfony):

```php
use GuzzleHttp\Psr7\HttpFactory;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;

$provider = new VutOpenIDConnectProvider($options, [
	'httpClient' => new Psr18Client(HttpClient::create(), new HttpFactory(), new HttpFactory()),
]);
```

### Exceptions

| Exception | When |
|---|---|
| `Exception\InvalidAuthorizationResponseException` | `state` or `iss` mismatch, missing `code` |
| `Exception\AuthorizationErrorException` | The authorization server returned an error (`getError()`, `getErrorDescription()`) |
| `Exception\InvalidTokenException` | ID token or logout token failed signature or claim validation |
| `Exception\InvalidConfigurationException` | Invalid options or discovery document |
| `League\OAuth2\Client\Provider\Exception\IdentityProviderException` | Error response from the token, revocation or userinfo endpoint |

## Run the example

```bash
OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... php -S localhost:8002 -t examples
```

Then open [http://localhost:8002/client.php](http://localhost:8002/client.php). The redirect URI
`http://localhost:8002/client.php` must be registered for the client.

Client credentials from the command line:

```bash
OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... OIDC_SCOPES="thiefReadonly" php examples/client-credentials.php
```

## Development

```bash
composer install
composer test      # composer audit + PHPStan + PHPUnit
```
