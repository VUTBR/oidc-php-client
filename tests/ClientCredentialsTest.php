<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\RequestInterface;
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
		self::assertSame(
			'Basic ' . base64_encode(TokenFactory::CLIENT_ID . ':' . TokenFactory::CLIENT_SECRET),
			$request->getHeaderLine('Authorization')
		);
		self::assertSame(
			['grant_type' => 'client_credentials', 'scope' => 'thiefReadonly userGroups', 'resource' => 'https://api.example/'],
			self::formBody($request)
		);
	}

	public function testPkceVerifierIsNotSent(): void
	{
		$provider = $this->createClientCredentialsProvider();
		$provider->setPkceCode(TokenFactory::PKCE);
		$this->queueJson(['access_token' => 'access-cc']);

		$provider->getAccessToken('client_credentials');

		self::assertArrayNotHasKey('code_verifier', self::formBody($this->lastRequest()));
	}

	public function testMultipleResources(): void
	{
		$provider = $this->createClientCredentialsProvider(['tokenEndpointAuthMethod' => 'client_secret_post']);
		$this->queueJson(['access_token' => 'access-cc']);

		$provider->getAccessToken('client_credentials', ['resource' => ['https://a.example/', 'https://b.example/']]);

		$body = (string)$this->lastRequest()->getBody();
		self::assertStringContainsString('client_secret=', $body);
		self::assertStringContainsString('resource=https%3A%2F%2Fa.example%2F&resource=https%3A%2F%2Fb.example%2F', $body);
	}

	public function testAuthenticatedApiRequest(): void
	{
		$provider = $this->createClientCredentialsProvider();
		$this->queueJson(['access_token' => 'access-cc']);
		$token = $provider->getAccessToken('client_credentials');

		$request = $provider->getAuthenticatedRequest('GET', 'https://api.example/resource', $token);

		self::assertInstanceOf(RequestInterface::class, $request);
		self::assertSame('Bearer access-cc', $request->getHeaderLine('Authorization'));
	}

	public function testInvalidScope(): void
	{
		$provider = $this->createClientCredentialsProvider();
		$this->queueJson(['error' => 'invalid_scope', 'error_description' => 'The requested scope is invalid'], 400);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage('invalid_scope');

		$provider->getAccessToken('client_credentials', ['scope' => 'unknown']);
	}
}
