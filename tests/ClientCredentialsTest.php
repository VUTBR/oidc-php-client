<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Provider\VutProvider;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

/**
 * Server-to-server access tokens with VutProvider (no discovery, no ID token).
 */
class ClientCredentialsTest extends ProviderTestCase
{
	/**
	 * @param array<string, mixed> $options
	 */
	private function createClientCredentialsProvider(array $options = []): VutProvider
	{
		$this->history = [];
		$this->mockHandler = new MockHandler();
		$stack = HandlerStack::create($this->mockHandler);
		$stack->push(Middleware::history($this->history));

		return new VutProvider(
			$options + [
				'clientId' => TokenFactory::CLIENT_ID,
				'clientSecret' => TokenFactory::CLIENT_SECRET,
			],
			['httpClient' => new Client(['handler' => $stack])]
		);
	}

	public function testClientCredentials(): void
	{
		$provider = $this->createClientCredentialsProvider();
		$this->queueJson(['access_token' => 'access-cc', 'token_type' => 'Bearer', 'expires_in' => 600, 'scope' => 'thiefReadonly userGroups']);

		$token = $provider->getAccessToken('client_credentials', [
			'scope' => ['thiefReadonly', 'userGroups'],
			'resource' => 'https://api.example/',
		]);

		self::assertInstanceOf(AccessToken::class, $token);
		self::assertSame('access-cc', $token->getToken());
		self::assertSame(['thiefReadonly', 'userGroups'], $token->getScopes());
		self::assertNull($token->getRefreshToken());
		self::assertFalse($token->hasExpired());
		// no HTTP request other than the token request (no discovery)
		self::assertCount(1, $this->history);

		$request = $this->lastRequest();
		self::assertSame('https://id.vut.cz/auth/common/oauth2/token', (string)$request->getUri());
		self::assertSame('', $request->getHeaderLine('Authorization'));
		self::assertSame(
			[
				'client_id' => TokenFactory::CLIENT_ID,
				'client_secret' => TokenFactory::CLIENT_SECRET,
				'grant_type' => 'client_credentials',
				'scope' => 'thiefReadonly userGroups',
				'resource' => 'https://api.example/',
			],
			self::formBody($request)
		);
	}
}
