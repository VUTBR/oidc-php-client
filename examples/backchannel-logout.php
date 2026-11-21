<?php
declare(strict_types=1);

/**
 * OpenID Connect Back-Channel Logout endpoint.
 *
 * Register its URL (e.g. https://app.example/backchannel-logout.php) as the back-channel logout URI
 * of the client at id.vut.cz. When the user logs out at id.vut.cz, the server POSTs a signed
 * `logout_token` here; the application validates it and ends the matching local sessions.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;

require __DIR__ . '/bootstrap.php';

header('Cache-Control: no-store');
header('Content-Type: application/json');

$logoutToken = $_POST['logout_token'] ?? null;
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !is_string($logoutToken) || $logoutToken === '') {
	http_response_code(400);
	echo json_encode(['error' => 'invalid_request']);
	return;
}

try {
	// Verifies typ, the signature, iss, aud, iat/exp, jti, sub|sid, the logout event and the absence of nonce
	$token = createProvider()->getLogoutToken($logoutToken, ['nbfToleranceSeconds' => 30]);
} catch (InvalidTokenException $e) {
	error_log('Back-channel logout rejected: ' . $e->getMessage());
	http_response_code(400);
	echo json_encode(['error' => 'invalid_request']);
	return;
}

$claims = $token->claims();
$sub = $claims->get('sub');
$sid = $claims->get('sid');

// Replays are not detected by the library. A production endpoint MUST reject a repeated iss + jti,
// stored atomically (e.g. a DB unique key or Redis SET NX with TTL) until `exp`.

foreach (sessionRegistry()->pullSessions(is_string($sub) ? $sub : null, is_string($sid) ? $sid : null) as $phpSessionId) {
	// Destroy the user's PHP session; the request comes from id.vut.cz, so it has no session of its own
	session_id($phpSessionId);
	session_start();
	$_SESSION = [];
	session_destroy();
}

http_response_code(200);
