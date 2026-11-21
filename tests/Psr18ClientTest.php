<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;
use Vut2\Component\OpenIDConnectClient\Test\Support\ArrayPsr18Client;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

class Psr18ClientTest extends ProviderTestCase
{
	private function createPsrProvider(ArrayPsr18Client $client): VutOpenIDConnectProvider
	{
		$client->append(self::json(self::discovery()));
		$client->append(self::json(self::jwks()));

		$provider = new VutOpenIDConnectProvider(
			[
				'clientId' => TokenFactory::CLIENT_ID,
				'clientSecret' => TokenFactory::CLIENT_SECRET,
				'redirectUri' => TokenFactory::REDIRECT_URI,
			],
			[
				'httpClient' => $client,
				'clock' => self::clock(),
			]
		);
		$provider->setNonce(TokenFactory::NONCE);
		$provider->setPkceCode(TokenFactory::PKCE);

		return $provider;
	}

	public function testDiscoveryAndTokenExchange(): void
	{
		$client = new ArrayPsr18Client();
		$provider = $this->createPsrProvider($client);
		$client->append(self::json([
			'access_token' => 'access-1',
			'id_token' => TokenFactory::idToken(),
		]));

		$token = $provider->getAccessToken('authorization_code', ['code' => 'the-code']);

		self::assertInstanceOf(IdToken::class, $token);
		self::assertSame($client, $provider->getPsrHttpClient());
		self::assertCount(3, $client->requests);
		self::assertSame('https://id.vut.cz/auth/.well-known/openid-configuration', (string)$client->requests[0]->getUri());
		self::assertSame('https://id.vut.cz/auth/common/oauth2/token', (string)$client->requests[2]->getUri());
		self::assertStringStartsWith('Basic ', $client->requests[2]->getHeaderLine('Authorization'));
	}

	public function testErrorResponseThrows(): void
	{
		$client = new ArrayPsr18Client();
		$provider = $this->createPsrProvider($client);
		$client->append(self::json(['error' => 'invalid_grant'], 400));

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage('invalid_grant');

		$provider->getAccessToken('authorization_code', ['code' => 'the-code']);
	}

	public function testRevokeWithPsr18Client(): void
	{
		$client = new ArrayPsr18Client();
		$provider = $this->createPsrProvider($client);
		$client->append(new Response(400));

		$this->expectException(IdentityProviderException::class);

		$provider->revokeAccessToken('access-1');
	}

	public function testUserInfo(): void
	{
		$client = new ArrayPsr18Client();
		$provider = $this->createPsrProvider($client);
		$client->append(self::json(['sub' => 'user-1', 'name' => 'Jana Nováková', 'given_name' => 'Jana', 'family_name' => 'Nováková']));

		$user = $provider->getResourceOwner(new \League\OAuth2\Client\Token\AccessToken(['access_token' => 'access-1']));

		self::assertSame('user-1', $user->getId());
		self::assertSame('Bearer access-1', $client->requests[2]->getHeaderLine('Authorization'));
		self::assertSame('https://id.vut.cz/auth/oidc/userinfo', (string)$client->requests[2]->getUri());
	}
}
