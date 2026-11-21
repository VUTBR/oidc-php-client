<?php
declare(strict_types=1);

/**
 * Login with id.vut.cz (authorization code flow with PKCE, OpenID Connect).
 *
 * Run: OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... php -S localhost:8002 -t examples
 * Open: http://localhost:8002/client.php
 */

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Vut2\Component\OpenIDConnectClient\Exception\AuthorizationErrorException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidAuthorizationResponseException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;

require __DIR__ . '/bootstrap.php';

ini_set('session.use_strict_mode', '1');
session_start();

$provider = createProvider();
$action = $_GET['action'] ?? null;

// 1) RP-initiated logout
if ($action === 'logout') {
	$idToken = $_SESSION['id_token'] ?? null;
	sessionRegistry()->unregister(session_id());
	$_SESSION = [];
	session_destroy();

	header('Location: ' . $provider->getLogoutUrl([
			'id_token_hint' => is_string($idToken) ? $idToken : null,
			'post_logout_redirect_uri' => 'http://localhost:8002/client.php',
		]));
	return;
}

// 2) Redirect back from id.vut.cz
if (isset($_GET['code']) || isset($_GET['error'])) {
	$state = $_SESSION['oauth2_state'] ?? '';
	$nonce = $_SESSION['oauth2_nonce'] ?? null;
	$pkce = $_SESSION['oauth2_pkce'] ?? null;
	$requirements = $_SESSION['oauth2_requirements'] ?? [];
	unset($_SESSION['oauth2_state'], $_SESSION['oauth2_nonce'], $_SESSION['oauth2_pkce'], $_SESSION['oauth2_requirements']);

	try {
		$code = $provider->validateAuthorizationResponse($_GET, (string)$state);

		$provider->setNonce($nonce);
		$provider->setPkceCode($pkce);
		$provider->setAuthorizationRequirements($requirements); // acr_values, max_age
		$token = $provider->getAccessToken('authorization_code', [
			'code' => $code,
			'nbfToleranceSeconds' => 30, // tolerated clock skew between id.vut.cz and this server
		]);
	} catch (AuthorizationErrorException $e) {
		// e.g. access_denied, login_required, unmet_authentication_requirements (acr_values)
		http_response_code(400);
		echo 'Login failed: ' . e($e->getError());
		return;
	} catch (InvalidAuthorizationResponseException | InvalidTokenException $e) {
		http_response_code(400);
		echo 'Invalid response from the identity provider.';
		error_log($e->getMessage());
		return;
	} catch (IdentityProviderException $e) {
		http_response_code(502);
		echo 'The identity provider rejected the request.';
		error_log($e->getMessage());
		return;
	}

	if (!$token instanceof IdToken || $token->getIdToken() === null) {
		throw new \LogicException('An ID token is always returned for the authorization code grant.');
	}

	// The application needs these scopes; the server may grant fewer.
	// An empty list means "as requested" (RFC 6749 §5.1).
	$granted = $token->getScopes();
	$missing = $granted === [] ? [] : array_diff(['openid', 'profile', 'email'], $granted);
	if ($missing !== []) {
		http_response_code(403);
		echo 'Missing permissions: ' . e(implode(', ', $missing));
		return;
	}

	$claims = $token->getIdToken()->claims();

	// Prevent session fixation and remember the session for back-channel logout
	session_regenerate_id(true);
	$_SESSION['user'] = [
		'sub' => $claims->get('sub'),
		'name' => $claims->get('name'),
		'email' => $claims->get('email'),
	];
	$_SESSION['id_token'] = $token->getIdToken()->toString();
	// the whole token incl. expirations and scopes, restorable with new AccessToken(json_decode(...))
	$_SESSION['token'] = json_encode($token);
	$sid = $claims->get('sid');
	sessionRegistry()->register(session_id(), (string)$claims->get('sub'), is_string($sid) ? $sid : null);

	header('Location: client.php');
	return;
}

// 3) Logged in
if (isset($_SESSION['user'])) {
	$token = new AccessToken((array)json_decode((string)$_SESSION['token'], true));

	if ($action === 'refresh' && $token->getRefreshToken() !== null) {
		$newToken = $provider->getAccessToken('refresh_token', ['refresh_token' => $token->getRefreshToken()]);
		if ($newToken instanceof AccessToken) {
			// Refresh tokens are rotated, always keep the newest one
			$_SESSION['token'] = json_encode($newToken);
			$token = $newToken;
		}
	}

	$user = $_SESSION['user'];
	echo '<p>Logged in as <strong>' . e((string)$user['name']) . '</strong> (' . e((string)$user['email']) . ')</p>';
	echo '<p>Scopes: ' . e(implode(' ', $token->getScopes())) . '<br>';
	echo 'Access token expires: ' . e(date('c', (int)$token->getExpires())) . '<br>';
	$refreshExpires = $token->getRefreshTokenExpires();
	echo 'Refresh token expires: ' . e($refreshExpires !== null ? date('c', $refreshExpires) : 'unknown') . '</p>';
	echo '<p><a href="?action=refresh">Refresh token</a> | <a href="?action=logout">Log out</a></p>';
	return;
}

// 4) Start the login: remember state, nonce, the PKCE verifier and acr_values/max_age for the redirect back
$authorizationUrl = $provider->getAuthorizationUrl([
	// 'acr_values' => ['urn:mfa'],
	// 'max_age' => 3600,
]);
$_SESSION['oauth2_state'] = $provider->getState();
$_SESSION['oauth2_nonce'] = $provider->getNonce();
$_SESSION['oauth2_pkce'] = $provider->getPkceCode();
$_SESSION['oauth2_requirements'] = $provider->getAuthorizationRequirements();

header('Location: ' . $authorizationUrl);
