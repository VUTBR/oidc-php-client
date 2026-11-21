<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TestKeys;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

class LogoutTest extends ProviderTestCase
{
	public function testValidLogoutToken(): void
	{
		$provider = $this->createProvider();

		$token = $provider->getLogoutToken(TokenFactory::logoutToken());

		self::assertSame('user-1', $token->claims()->get('sub'));
		self::assertSame('session-1', $token->claims()->get('sid'));
	}

	public function testLogoutTokenWithSidOnly(): void
	{
		$provider = $this->createProvider();

		$token = $provider->getLogoutToken(TokenFactory::logoutToken(['sub' => null]));

		self::assertSame('session-1', $token->claims()->get('sid'));
	}

	/**
	 * @return array<string, array{array<string, mixed>, string}>
	 */
	public static function invalidLogoutTokens(): array
	{
		return [
			'nonce present' => [['nonce' => 'n'], 'nonce'],
			'missing jti' => [['jti' => null], 'jti'],
			'missing iat' => [['iat' => null], 'Issued At'],
			'missing sub and sid' => [['sub' => null, 'sid' => null], 'sub'],
			'missing events' => [['events' => null], 'events'],
			'wrong event' => [['events' => ['http://schemas.openid.net/event/other' => new \stdClass()]], 'events'],
			'wrong issuer' => [['iss' => 'https://attacker.example'], 'iss'],
			'wrong audience' => [['aud' => 'other-client'], 'aud'],
			'expired' => [['iat' => TokenFactory::NOW - 7200, 'exp' => TokenFactory::NOW - 3600], 'expired'],
		];
	}

	/**
	 * @dataProvider invalidLogoutTokens
	 * @param array<string, mixed> $claims
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('invalidLogoutTokens')]
	public function testInvalidLogoutToken(array $claims, string $message): void
	{
		$provider = $this->createProvider();

		try {
			$provider->getLogoutToken(TokenFactory::logoutToken($claims));
			self::fail('Expected InvalidTokenException');
		} catch (InvalidTokenException $e) {
			self::assertStringContainsStringIgnoringCase($message, $e->getMessage());
		}
	}

	public function testLogoutTokenWithInvalidSignature(): void
	{
		$provider = $this->createProvider();
		$parts = explode('.', TokenFactory::logoutToken());
		$parts[2] = TestKeys::base64Url(str_repeat('x', 256));

		$this->expectException(InvalidTokenException::class);
		$this->expectExceptionMessage('invalid logout_token');

		$provider->getLogoutToken(implode('.', $parts));
	}

	public function testMalformedLogoutToken(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidTokenException::class);

		$provider->getLogoutToken('not-a-jwt');
	}

	public function testLogoutUrl(): void
	{
		$provider = $this->createProvider();

		$url = $provider->getLogoutUrl([
			'id_token_hint' => 'id.token.value',
			'post_logout_redirect_uri' => 'https://app.example/logged-out',
			'state' => 'logout-state',
		]);

		self::assertStringStartsWith('https://id.vut.cz/auth/common/oauth2/endSession?', $url);
		self::assertSame([
			'client_id' => TokenFactory::CLIENT_ID,
			'id_token_hint' => 'id.token.value',
			'post_logout_redirect_uri' => 'https://app.example/logged-out',
			'state' => 'logout-state',
		], self::query($url));
	}

	public function testLogoutUrlKeepsPortAndQuery(): void
	{
		$provider = $this->createProvider([], self::discovery(['end_session_endpoint' => 'https://id.example:8443/logout?tenant=vut']));

		$url = $provider->getLogoutUrl();

		self::assertSame('https://id.example:8443/logout?tenant=vut&client_id=' . TokenFactory::CLIENT_ID, $url);
	}
}
