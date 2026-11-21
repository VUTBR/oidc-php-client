# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PHP library `vutbr/oidc-client` (namespace `Vut2\Component\OpenIDConnectClient\`, PSR-4 from `src/`): an OAuth 2.1 / OpenID Connect client for the VUT identity provider (`https://id.vut.cz/auth`). Built on `league/oauth2-client` (provider/grant/token plumbing) and `lcobucci/jwt` (JWT parsing, signature checks), with `phpseclib` for JWK→PEM conversion and RSA-PSS signatures. Only confidential (back-end) clients with a `client_secret` are supported.

## Compatibility constraints

The code must run on **PHP 7.4 up to the latest PHP (8.6)** while allowing the newest dependency majors. No PHP 8-only syntax or functions (constructor promotion, `match`, union types in signatures, named args, `mixed`, `str_contains`/`str_starts_with`, enums, readonly). `composer.json` deliberately has no `config.platform` pin and no committed lock file, so each PHP version resolves its own dependencies:

- `lcobucci/jwt` 4.3 (PHP 7.4–8.0) or 5.x (5.7 needs PHP 8.4+). Use only APIs present in both. Don't use `LooseValidAt`/`StrictValidAt` (deprecated in 5.7, and their clock type differs between 4 and 5); time checks are in the own `Constraint\ValidAt`. jwt 5 requires `non-empty-string` in many places (PHPStan enforces it).
- `lcobucci/clock` 2 or 3. Internal code only relies on `now()`.
- `phpseclib` 3 (namespace `phpseclib3\`) or 4 (namespace `phpseclib4\`, PHP 8.1+). Never reference phpseclib classes directly; go through `Crypto\Phpseclib`, which resolves the namespace at runtime.
- Guzzle 7 or 8, PHPUnit 9.6–12 (tests use both the `@dataProvider` annotation and the `#[DataProvider]` attribute).
- Minimum versions in `composer.json` are raised past known security advisories (`composer audit` runs in CI, including `--prefer-lowest`).

## Commands

```bash
composer install
composer test        # composer audit + phpstan + phpunit (what CI checks)
composer phpstan     # PHPStan level 8 on src/
composer phpunit     # all tests, writes phpunit-report.xml

vendor/bin/phpunit tests/TokenExchangeTest.php        # one file
vendor/bin/phpunit --filter testMaxAge                # one test by name

OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... php -S localhost:8002 -t examples   # demo client
```

To check PHP 7.4 locally, copy the project to a temp directory and run `composer update --prefer-lowest` with the PHP 7.4 binary there (Homebrew `php@7.4`), so the main `vendor/` is not replaced. Other versions: resolve with `composer config platform.php 8.x.0` and run in Docker (`php:8.x-cli`).

PHPStan includes `spaze/phpstan-disallowed-calls` rule sets plus `disallowed-insecure-calls.neon` (bans `var_dump`, `print_r`, `dd`, `bdump`, …) for `src/`.

## Code style

Per `.editorconfig`: tabs (width 4) for PHP, 2 spaces for JSON/YAML/Markdown, LF line endings. Source files use `declare(strict_types=1);`.

## Architecture

Class hierarchy: `League GenericProvider` → `Provider\VutProvider` → `Provider\VutOpenIDConnectProvider`.

- **`VutProvider`**: OAuth 2.1 layer.
  - Requires `clientSecret`, forces PKCE `S256` and fills default endpoint URLs from `baseUrl` (default `https://id.vut.cz/auth` + `/common/oauth2/...`).
  - Picks the option provider by `tokenEndpointAuthMethod`: `OptionProvider\ClientSecretBasicOptionProvider` (default) or `ClientSecretPostOptionProvider`. Both build bodies via `Tool\QueryString`, which sends list values as repeated params (RFC 8707 `resource`).
  - **HTTP**: league only accepts Guzzle. A PSR-18 `httpClient` collaborator is split off in `initPsrHttpClient()` and used by the overridden `getResponse()`.
  - `getAccessToken()` requires the PKCE verifier for `authorization_code` and strips it for other grants.
  - Also handles revocation (`revokeAccessToken`) and RP-initiated logout (`getLogoutUrl`).
- **`VutOpenIDConnectProvider`**: OIDC layer.
  - **Discovery** runs in the constructor *before* `parent::__construct`, so the request factory and HTTP client (Guzzle or PSR-18) are set up first. Without `issuer` and `publicKey` it uses the default issuer.
    - The document's `issuer` must equal the configured one.
    - Discovered values only fill options not passed explicitly.
    - It reads the alg allow-list, `authorization_response_iss_parameter_supported`, PKCE methods and token auth methods.
    - The JWKS is filtered (`use=sig`, allowed `alg`) and converted to PEM keyed by `kid`.
    - Discovery and PEM keys are cached for 1h when a PSR-6 `cache` is given.
  - **`verifySignature()`**: an `alg` allow-list (never `none`).
    - Asymmetric algorithms are verified only with the issuer keys (the `kid` match first, otherwise all keys).
    - `HS*` is verified only with the client secret, which prevents algorithm confusion.
    - Signers come from the `SIGNERS` map; PS* use the own `Signer\RsaPss\*`.
  - **`getAccessToken()`**:
    - Removes the client-side validation options (`nbfToleranceSeconds`, `maxAge`, `requireAuthTime`, `acrValues`) before calling parent, so they are never sent to the server.
    - Requires the nonce for `authorization_code`.
    - `createAccessToken` returns `Flow\IdToken` when `id_token` is present, otherwise `Flow\AccessToken`. Both have `getScopes()`, which reads `scope` with a fallback to the legacy `scopes`.
    - ID tokens are validated in `validateIdToken()` (also for refresh responses, without the nonce) using constraints from `Constraint/`.
  - **`validateAuthorizationResponse()`**: checks `iss` (RFC 9207), then `state`, then the error response, and returns the code.
  - **`getLogoutToken()`**: validates back-channel logout tokens (`HasBackchannelLogoutEvent`, `HasSubOrSid`, `DoesNotHaveClaim('nonce')`, `jti`, iat/exp).
  - The nonce, state and PKCE verifier live on the provider instance. Callers persist them across the redirect with `getNonce`/`setNonce` and `getPkceCode`/`setPkceCode`.
- `Flow\AccessToken` is a minimal league `AccessToken`: `getScopes()` splits `scope` (fallback legacy `scopes`), and `refresh_expires_in` is kept as an absolute `refresh_expires` (like league `expires_in` → `expires`) so it survives `jsonSerialize()`. Keep it league-like and avoid extra provider state.
- The two typical uses are OIDC login (`VutOpenIDConnectProvider`) and `client_credentials`. For `client_credentials`, plain `VutProvider` is enough: no discovery, no ID token, and it returns `Flow\AccessToken` (covered by `tests/ClientCredentialsTest.php`).
- `examples/` contains a runnable login client, a `client_credentials` CLI script with token caching, and a back-channel logout endpoint with a file-based `SessionRegistry`.

## Tests

- **Support code** in `tests/Support/`:
  - `ProviderTestCase` builds a provider over Guzzle `MockHandler` with history (queue order: discovery, JWKS, then token responses) and a `FrozenClock` at `TokenFactory::NOW`.
  - `TokenFactory` signs ID and logout tokens with RSA keys generated at runtime (`TestKeys`).
  - `ArrayPsr18Client` is a PSR-18 stub.
- `VutOpenIDConnectProviderTest` is a regression test against real BankID sandbox discovery/JWKS and a real PS512 token.
- All tests run offline.
