<?php
declare(strict_types=1);

/**
 * Server-to-server access token (client_credentials grant), e.g. for calling a VUT API from a cron job.
 *
 * Run:
 *   OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... OIDC_SCOPES="thiefReadonly userGroups" php examples/client-credentials.php
 *
 * Optional: OIDC_RESOURCE=https://api.example/ (RFC 8707 resource indicator)
 */

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Provider\VutProvider;

require __DIR__ . '/../vendor/autoload.php';

// VutProvider is enough for client_credentials: no discovery request, no ID token validation.
$provider = new VutProvider([
	'clientId' => (string)getenv('OIDC_CLIENT_ID'),
	'clientSecret' => (string)getenv('OIDC_CLIENT_SECRET'),
]);

/**
 * Returns a cached token while it is valid, otherwise requests a new one.
 * client_credentials has no refresh token - simply request a new access token when it expires.
 *
 * @param array<string, mixed> $options
 */
function getCachedToken(VutProvider $provider, array $options, string $cacheFile): AccessToken
{
	$cached = is_file($cacheFile) ? json_decode((string)file_get_contents($cacheFile), true) : null;
	if (is_array($cached)) {
		$token = new AccessToken($cached);
		// renew one minute before expiry
		if ($token->getExpires() === null || $token->getExpires() - 60 > time()) {
			return $token;
		}
	}

	$token = $provider->getAccessToken('client_credentials', $options);
	if (!$token instanceof AccessToken) {
		throw new \UnexpectedValueException('Unexpected token type.');
	}

	file_put_contents($cacheFile, json_encode($token), LOCK_EX);
	chmod($cacheFile, 0600);

	return $token;
}

$options = [];
$scopes = trim((string)getenv('OIDC_SCOPES'));
if ($scopes !== '') {
	$options['scope'] = preg_split('/\s+/', $scopes);
}
$resource = (string)getenv('OIDC_RESOURCE');
if ($resource !== '') {
	$options['resource'] = $resource;
}

try {
	$token = getCachedToken($provider, $options, sys_get_temp_dir() . '/oidc-client-example-cc-token.json');
} catch (IdentityProviderException $e) {
	// e.g. invalid_client (wrong credentials) or invalid_scope (scope not allowed for the client)
	fwrite(STDERR, 'Token request failed: ' . $e->getMessage() . PHP_EOL);
	exit(1);
}

echo 'Access token: ' . substr($token->getToken(), 0, 20) . '...' . PHP_EOL;
echo 'Expires:      ' . ($token->getExpires() !== null ? date('c', $token->getExpires()) : 'n/a') . PHP_EOL;
echo 'Scopes:       ' . implode(' ', $token->getScopes()) . PHP_EOL;

// Calling an API with the token (any HTTP client works, the header is "Authorization: Bearer <token>"):
// $request = $provider->getAuthenticatedRequest('GET', 'https://api.example/resource', $token);
// $response = $provider->getResponse($request);
