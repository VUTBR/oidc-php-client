<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

/**
 * Fields of token responses as produced by id.vut.cz (league/oauth2-server IdTokenResponse).
 */
class TokenResponseTest extends TestCase
{
	protected function setUp(): void
	{
		AccessToken::setTimeNow(TokenFactory::NOW);
	}

	protected function tearDown(): void
	{
		AccessToken::resetTimeNow();
	}

	public function testRefreshTokenExpiration(): void
	{
		$token = new AccessToken([
			'token_type' => 'Bearer',
			'expires_in' => 3600,
			'access_token' => 'access-1',
			'refresh_token' => 'refresh-1',
			'refresh_expires_in' => 2592000,
			'scopes' => 'openid profile',
		]);

		self::assertSame(TokenFactory::NOW + 3600, $token->getExpires());
		self::assertSame(TokenFactory::NOW + 2592000, $token->getRefreshTokenExpires());
		self::assertArrayNotHasKey('refresh_expires_in', $token->getValues());
		// raw response values stay available as in league
		self::assertSame('openid profile', $token->getValues()['scopes']);

		self::assertNull((new AccessToken(['access_token' => 'a']))->getRefreshTokenExpires());
	}

	public function testSerializationRoundTrip(): void
	{
		$token = new AccessToken([
			'access_token' => 'access-1',
			'refresh_token' => 'refresh-1',
			'expires_in' => 3600,
			'refresh_expires_in' => 7200,
			'scopes' => 'openid profile',
		]);

		AccessToken::setTimeNow(TokenFactory::NOW + 100);
		$restored = new AccessToken((array)json_decode((string)json_encode($token), true));

		self::assertSame('refresh-1', $restored->getRefreshToken());
		self::assertSame(TokenFactory::NOW + 3600, $restored->getExpires());
		self::assertSame(TokenFactory::NOW + 7200, $restored->getRefreshTokenExpires());
		self::assertSame(['openid', 'profile'], $restored->getScopes());
	}

	public function testIdTokenSerializationRoundTrip(): void
	{
		// e.g. stored with json_encode() in Redis or the session
		$token = new IdToken([
			'access_token' => 'access-1',
			'refresh_expires_in' => 7200,
			'id_token' => TokenFactory::idToken(),
			'scopes' => 'openid profile',
		]);

		$restored = new IdToken((array)json_decode((string)json_encode($token), true));

		self::assertSame(TokenFactory::NOW + 7200, $restored->getRefreshTokenExpires());
		self::assertNotNull($restored->getIdToken());
		self::assertSame('user-1', $restored->getIdToken()->claims()->get('sub'));
		self::assertSame(['openid', 'profile'], $restored->getScopes());
	}

	/**
	 * @return array<string, array{array<string, mixed>, array<string>}>
	 */
	public static function scopeResponses(): array
	{
		return [
			'scope' => [['scope' => 'openid email'], ['openid', 'email']],
			'legacy scopes' => [['scopes' => 'openid email'], ['openid', 'email']],
			'scope takes precedence' => [['scope' => 'openid', 'scopes' => 'openid email'], ['openid']],
			// RFC 6749 §5.1: identical to the requested scope
			'omitted' => [[], []],
			'null' => [['scopes' => null], []],
			'empty' => [['scope' => ''], []],
		];
	}

	/**
	 * @dataProvider scopeResponses
	 * @param array<string, mixed> $scopeFields
	 * @param array<string> $expected
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('scopeResponses')]
	public function testGetScopes(array $scopeFields, array $expected): void
	{
		$token = new AccessToken(['access_token' => 'a'] + $scopeFields);

		self::assertSame($expected, $token->getScopes());
	}
}
