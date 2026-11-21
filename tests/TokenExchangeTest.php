<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use Lcobucci\JWT\Signer;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;
use Vut2\Component\OpenIDConnectClient\Provider\VutUser;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TestKeys;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

class TokenExchangeTest extends ProviderTestCase
{
	/**
	 * @param array<string, mixed> $idTokenClaims
	 * @param array<string, mixed> $extra
	 */
	private function queueTokenResponse(array $idTokenClaims = [], array $extra = []): void
	{
		$this->queueJson($extra + [
			'access_token' => 'access-1',
			'token_type' => 'Bearer',
			'expires_in' => 3600,
			'refresh_token' => 'refresh-1',
			'id_token' => TokenFactory::idToken($idTokenClaims),
			'scope' => 'openid profile email',
			'scopes' => 'openid profile email',
		]);
	}

	public function testAuthorizationCodeExchange(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse();

		$token = $provider->getAccessToken('authorization_code', ['code' => 'the-code', 'nbfToleranceSeconds' => 30]);

		self::assertInstanceOf(IdToken::class, $token);
		self::assertSame('access-1', $token->getToken());
		self::assertSame('refresh-1', $token->getRefreshToken());
		self::assertSame(['openid', 'profile', 'email'], $token->getScopes());
		self::assertNotNull($token->getIdToken());
		self::assertSame('user-1', $token->getIdToken()->claims()->get('sub'));

		$request = $this->lastRequest();
		$body = self::formBody($request);
		self::assertSame('https://id.vut.cz/auth/common/oauth2/token', (string)$request->getUri());
		self::assertSame(
			'Basic ' . base64_encode(TokenFactory::CLIENT_ID . ':' . TokenFactory::CLIENT_SECRET),
			$request->getHeaderLine('Authorization')
		);
		self::assertSame('authorization_code', $body['grant_type']);
		self::assertSame('the-code', $body['code']);
		self::assertSame(TokenFactory::PKCE, $body['code_verifier']);
		self::assertSame(TokenFactory::REDIRECT_URI, $body['redirect_uri']);
		self::assertArrayNotHasKey('client_secret', $body);
		// client-side validation options are never sent to the server
		self::assertArrayNotHasKey('nbfToleranceSeconds', $body);

		$user = $provider->getResourceOwner($token);
		self::assertInstanceOf(VutUser::class, $user);
		self::assertSame('user-1', $user->getId());
		self::assertSame('jana@example.com', $user->getEmail());
	}

	public function testClientSecretPost(): void
	{
		$provider = $this->createProviderAfterRedirect(['tokenEndpointAuthMethod' => 'client_secret_post']);
		$this->queueTokenResponse();

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);

		$request = $this->lastRequest();
		$body = self::formBody($request);
		self::assertSame('', $request->getHeaderLine('Authorization'));
		self::assertSame(TokenFactory::CLIENT_ID, $body['client_id']);
		self::assertSame(TokenFactory::CLIENT_SECRET, $body['client_secret']);
	}

	public function testResourceIsSentAsRepeatedParameter(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse();

		$provider->getAccessToken('authorization_code', ['code' => 'the-code', 'resource' => ['https://a.example/', 'https://b.example/']]);

		self::assertStringContainsString(
			'resource=https%3A%2F%2Fa.example%2F&resource=https%3A%2F%2Fb.example%2F',
			(string)$this->lastRequest()->getBody()
		);
	}

	public function testMissingNonceIsALogicError(): void
	{
		$provider = $this->createProvider();
		$provider->setPkceCode(TokenFactory::PKCE);

		$this->expectException(\LogicException::class);
		$this->expectExceptionMessage('Nonce is missing');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testMissingPkceIsALogicError(): void
	{
		$provider = $this->createProvider();
		$provider->setNonce(TokenFactory::NONCE);

		$this->expectException(\LogicException::class);
		$this->expectExceptionMessage('PKCE code verifier is missing');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testMissingIdTokenIsRejected(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueJson(['access_token' => 'access-1', 'token_type' => 'Bearer']);

		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('Expected an id_token');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	/**
	 * @return array<string, array{array<string, mixed>, string}>
	 */
	public static function invalidClaims(): array
	{
		return [
			'wrong nonce' => [['nonce' => 'other'], 'nonce'],
			'missing nonce' => [['nonce' => null], 'nonce'],
			'wrong issuer' => [['iss' => 'https://attacker.example'], 'iss'],
			'wrong audience' => [['aud' => 'other-client'], 'aud'],
			'expired' => [['iat' => TokenFactory::NOW - 7200, 'exp' => TokenFactory::NOW - 3600], 'expired'],
			'missing exp' => [['exp' => null], 'Expiration'],
			'missing iat' => [['iat' => null], 'Issued At'],
			'issued in the future' => [['iat' => TokenFactory::NOW + 3600, 'exp' => TokenFactory::NOW + 7200], 'future'],
			'not yet valid' => [['nbf' => TokenFactory::NOW + 3600], 'cannot be used yet'],
			'missing sub' => [['sub' => null], 'sub'],
			'wrong azp' => [['azp' => 'other-client'], 'azp'],
		];
	}

	/**
	 * @dataProvider invalidClaims
	 * @param array<string, mixed> $claims
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('invalidClaims')]
	public function testInvalidIdTokenClaims(array $claims, string $message): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse($claims);

		try {
			$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
			self::fail('Expected InvalidTokenException');
		} catch (InvalidTokenException $e) {
			self::assertStringContainsStringIgnoringCase($message, $e->getMessage());
		}
	}

	public function testLeewayToleratesClockSkew(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse(['iat' => TokenFactory::NOW + 20, 'exp' => TokenFactory::NOW + 600]);

		$token = $provider->getAccessToken('authorization_code', ['code' => 'the-code', 'nbfToleranceSeconds' => 30]);

		self::assertInstanceOf(IdToken::class, $token);
	}

	public function testAudienceValidationCanBeDisabled(): void
	{
		$provider = $this->createProviderAfterRedirect(['validateAudience' => false]);
		$this->queueTokenResponse(['aud' => 'other-client']);

		self::assertInstanceOf(IdToken::class, $provider->getAccessToken('authorization_code', ['code' => 'the-code']));
	}

	public function testMultipleAudiencesIncludingClient(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse(['aud' => [TokenFactory::CLIENT_ID, 'https://api.example/'], 'azp' => TokenFactory::CLIENT_ID]);

		self::assertInstanceOf(IdToken::class, $provider->getAccessToken('authorization_code', ['code' => 'the-code']));
	}

	public function testTokenSignedWithUnknownKeyIsRejected(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueJson([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::idToken([], ['kid' => 'other'], null, TestKeys::rsa('other')['private']),
		]);

		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('invalid id_token');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testHmacTokenSignedWithPublicKeyIsRejected(): void
	{
		// algorithm confusion: attacker signs HS256 using the published public key as the secret
		$provider = $this->createProviderAfterRedirect();
		$this->queueJson([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::idToken([], [], new Signer\Hmac\Sha256(), TestKeys::rsa()['public']),
		]);

		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('disallowed algorithm "HS256"');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testHmacTokenIsVerifiedOnlyWithClientSecret(): void
	{
		$provider = $this->createProviderAfterRedirect(['idTokenSigningAlgValues' => ['RS256', 'HS256']]);
		$this->queueJson([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::idToken([], [], new Signer\Hmac\Sha256(), TestKeys::rsa()['public']),
		]);

		try {
			$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
			self::fail('A token signed with the public key as HMAC secret must be rejected.');
		} catch (InvalidTokenException $e) {
			self::assertStringContainsString('invalid id_token', $e->getMessage());
		}

		$this->queueJson([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::idToken([], [], new Signer\Hmac\Sha256(), TokenFactory::CLIENT_SECRET),
		]);
		self::assertInstanceOf(IdToken::class, $provider->getAccessToken('authorization_code', ['code' => 'the-code']));
	}

	public function testUnsignedTokenIsRejected(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueJson([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::unsigned(['iss' => TokenFactory::ISSUER, 'aud' => TokenFactory::CLIENT_ID, 'sub' => 'user-1']),
		]);

		$this->expectException(InvalidTokenException::class);

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testMaxAge(): void
	{
		$provider = $this->createProviderAfterRedirect();

		$this->queueTokenResponse(['auth_time' => TokenFactory::NOW - 100]);
		self::assertInstanceOf(IdToken::class, $provider->getAccessToken('authorization_code', ['code' => 'c', 'maxAge' => 300]));

		$this->queueTokenResponse(['auth_time' => TokenFactory::NOW - 600]);
		try {
			$provider->getAccessToken('authorization_code', ['code' => 'c', 'maxAge' => 300]);
			self::fail('Expected InvalidTokenException');
		} catch (InvalidTokenException $e) {
			self::assertStringContainsString('max_age', $e->getMessage());
		}

		$this->queueTokenResponse(['auth_time' => null]);
		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('auth_time');
		$provider->getAccessToken('authorization_code', ['code' => 'c', 'maxAge' => 300]);
	}

	public function testRequireAuthTime(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse(['auth_time' => null]);

		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('auth_time');

		$provider->getAccessToken('authorization_code', ['code' => 'c', 'requireAuthTime' => true]);
	}

	public function testAcrValues(): void
	{
		$provider = $this->createProviderAfterRedirect();

		$this->queueTokenResponse(['acr' => 'urn:mfa']);
		$token = $provider->getAccessToken('authorization_code', ['code' => 'c', 'acrValues' => 'urn:mfa urn:mfa:passwordless']);
		self::assertInstanceOf(IdToken::class, $token);
		self::assertArrayNotHasKey('acrValues', self::formBody($this->lastRequest()));

		$this->queueTokenResponse(['acr' => 'urn:untrusted']);
		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('acr');
		$provider->getAccessToken('authorization_code', ['code' => 'c', 'acrValues' => ['urn:mfa']]);
	}

	public function testRefreshTokenWithIdToken(): void
	{
		$provider = $this->createProviderAfterRedirect();
		// OIDC Core §12.2: the refreshed ID token does not need to carry the nonce
		$this->queueTokenResponse(['nonce' => null], ['refresh_token' => 'refresh-2']);

		$token = $provider->getAccessToken('refresh_token', ['refresh_token' => 'refresh-1']);

		self::assertInstanceOf(IdToken::class, $token);
		self::assertSame('refresh-2', $token->getRefreshToken());
		$body = self::formBody($this->lastRequest());
		self::assertSame('refresh_token', $body['grant_type']);
		self::assertSame('refresh-1', $body['refresh_token']);
		self::assertArrayNotHasKey('code_verifier', $body);
		// the PKCE verifier is kept for a later authorization code exchange
		self::assertSame(TokenFactory::PKCE, $provider->getPkceCode());
	}

	public function testRefreshedIdTokenIsValidated(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueTokenResponse(['iss' => 'https://attacker.example']);

		$this->expectException(InvalidTokenException::class);

		$provider->getAccessToken('refresh_token', ['refresh_token' => 'refresh-1']);
	}

	public function testRefreshTokenWithoutIdToken(): void
	{
		$provider = $this->createProvider();
		$this->queueJson(['access_token' => 'access-2', 'refresh_token' => 'refresh-2', 'scope' => 'openid offline_access']);

		$token = $provider->getAccessToken('refresh_token', ['refresh_token' => 'refresh-1']);

		self::assertInstanceOf(AccessToken::class, $token);
		self::assertNotInstanceOf(IdToken::class, $token);
		self::assertSame(['openid', 'offline_access'], $token->getScopes());
	}

	/**
	 * Usage as in existing applications: custom redirect_uri and scopes, extra authorization
	 * parameters, scopes read from the token response.
	 */
	public function testExistingApplicationUsage(): void
	{
		$provider = $this->createProvider();
		$url = $provider->getAuthorizationUrl([
			'redirect_uri' => 'https://app.example/openid/token',
			'scope' => ['openid', 'profile', 'email', 'thiefIpAddr', 'offline_access', 'trustedDevice'],
			'max_age' => 4 * 3600,
			'acr_values' => 'urn:mfa',
			'victim_id' => 5,
		]);
		$query = self::query($url);

		self::assertSame('https://app.example/openid/token', $query['redirect_uri']);
		self::assertSame('openid profile email thiefIpAddr offline_access trustedDevice', $query['scope']);
		self::assertSame('14400', $query['max_age']);
		self::assertSame('urn:mfa', $query['acr_values']);
		self::assertSame('5', $query['victim_id']);

		$provider->setNonce(TokenFactory::NONCE);
		$provider->setPkceCode(TokenFactory::PKCE);
		$this->queueTokenResponse([], ['scope' => null, 'scopes' => 'openid profile trustedDevice', 'refresh_expires_in' => 3600]);

		$token = $provider->getAccessToken('authorization_code', [
			'redirect_uri' => 'https://app.example/openid/token',
			'code' => 'the-code',
			'nbfToleranceSeconds' => 3600,
		]);

		self::assertInstanceOf(IdToken::class, $token);
		self::assertSame('https://app.example/openid/token', self::formBody($this->lastRequest())['redirect_uri']);
		self::assertContains('trustedDevice', $token->getScopes());
		self::assertSame('openid profile trustedDevice', $token->getValues()['scopes']);
		self::assertNotNull($token->getRefreshTokenExpires());
	}

	public function testClientCredentials(): void
	{
		$provider = $this->createProvider();
		$this->queueJson(['access_token' => 'access-cc', 'expires_in' => 600]);

		$token = $provider->getAccessToken('client_credentials');

		self::assertSame('access-cc', $token->getToken());
	}

	public function testTokenEndpointErrorThrows(): void
	{
		$provider = $this->createProviderAfterRedirect();
		$this->queueJson(['error' => 'invalid_grant', 'error_description' => 'Code expired'], 400);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage('invalid_grant');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testRevokeToken(): void
	{
		$provider = $this->createProvider();
		$this->mockHandler->append(new \GuzzleHttp\Psr7\Response(200));

		$response = $provider->revokeAccessToken('refresh-1', 'refresh_token');

		self::assertSame(200, $response->getStatusCode());
		$request = $this->lastRequest();
		self::assertSame('https://id.vut.cz/auth/common/oauth2/revoke', (string)$request->getUri());
		self::assertStringStartsWith('Basic ', $request->getHeaderLine('Authorization'));
		self::assertSame(['token' => 'refresh-1', 'token_type_hint' => 'refresh_token'], self::formBody($request));
	}

	public function testRevokeTokenFailure(): void
	{
		$provider = $this->createProvider();
		$this->queueJson(['error' => 'invalid_client'], 401);

		$this->expectException(IdentityProviderException::class);

		$provider->revokeAccessToken('refresh-1');
	}
}
