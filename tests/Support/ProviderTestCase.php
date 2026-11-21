<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test\Support;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

abstract class ProviderTestCase extends TestCase
{
	protected MockHandler $mockHandler;

	/** @var array<int, array{request: RequestInterface}> */
	protected array $history = [];

	/**
	 * Discovery document as currently published by id.vut.cz, optionally with the OAuth 2.1 additions.
	 *
	 * @param array<string, mixed> $overrides null removes the key
	 * @return array<string, mixed>
	 */
	public static function discovery(array $overrides = [], bool $oauth21 = false): array
	{
		$issuer = TokenFactory::ISSUER;
		$document = [
			'issuer' => $issuer,
			'authorization_endpoint' => $issuer . '/common/oauth2/authorize',
			'token_endpoint' => $issuer . '/common/oauth2/token',
			'userinfo_endpoint' => $issuer . '/oidc/userinfo',
			'jwks_uri' => $issuer . '/.well-known/jwks.json',
			'response_types_supported' => ['code'],
			'id_token_signing_alg_values_supported' => ['RS256'],
			'subject_types_supported' => ['pairwise'],
			'end_session_endpoint' => $issuer . '/common/oauth2/endSession',
			'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
			'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
			'frontchannel_logout_supported' => true,
			'revocation_endpoint' => $issuer . '/common/oauth2/revoke',
			'backchannel_logout_supported' => true,
			'backchannel_logout_session_supported' => true,
			'acr_values_supported' => ['urn:untrusted', 'urn:mfa', 'urn:mfa:passwordless', 'urn:mfa:phr'],
		];

		if ($oauth21) {
			$document['code_challenge_methods_supported'] = ['S256'];
			$document['token_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post', 'none'];
			$document['authorization_response_iss_parameter_supported'] = true;
		}

		foreach ($overrides as $key => $value) {
			if ($value === null) {
				unset($document[$key]);
			} else {
				$document[$key] = $value;
			}
		}

		return $document;
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function jwks(): array
	{
		return ['keys' => [TestKeys::rsa()['jwk']]];
	}

	/**
	 * @param array<mixed> $body
	 */
	public static function json(array $body, int $status = 200): Response
	{
		return new Response($status, ['Content-Type' => 'application/json'], (string)json_encode($body));
	}

	/**
	 * Creates a provider using discovery served by a mocked Guzzle client and a frozen clock.
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed>|null $discovery
	 * @param array<string, mixed> $collaborators
	 */
	protected function createProvider(array $options = [], ?array $discovery = null, array $collaborators = []): VutOpenIDConnectProvider
	{
		$this->history = [];
		$this->mockHandler = new MockHandler([
			self::json($discovery ?? self::discovery()),
			self::json(self::jwks()),
		]);
		$stack = HandlerStack::create($this->mockHandler);
		$stack->push(Middleware::history($this->history));

		return new VutOpenIDConnectProvider(
			$options + [
				'clientId' => TokenFactory::CLIENT_ID,
				'clientSecret' => TokenFactory::CLIENT_SECRET,
				'redirectUri' => TokenFactory::REDIRECT_URI,
				'scopes' => ['openid', 'profile', 'email'],
				'issuer' => TokenFactory::ISSUER,
			],
			$collaborators + [
				'httpClient' => new Client(['handler' => $stack]),
				'clock' => self::clock(),
			]
		);
	}

	public static function clock(int $timestamp = TokenFactory::NOW): FrozenClock
	{
		return new FrozenClock(new \DateTimeImmutable('@' . $timestamp));
	}

	/**
	 * Provider in the state after the redirect back: nonce and PKCE verifier restored.
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed>|null $discovery
	 */
	protected function createProviderAfterRedirect(array $options = [], ?array $discovery = null): VutOpenIDConnectProvider
	{
		$provider = $this->createProvider($options, $discovery);
		$provider->setNonce(TokenFactory::NONCE);
		$provider->setPkceCode(TokenFactory::PKCE);

		return $provider;
	}

	/**
	 * @param array<mixed> $body
	 */
	protected function queueJson(array $body, int $status = 200): void
	{
		$this->mockHandler->append(self::json($body, $status));
	}

	protected function lastRequest(): RequestInterface
	{
		$last = end($this->history);
		self::assertIsArray($last, 'No request was sent.');

		return $last['request'];
	}

	/**
	 * @return array<string, mixed>
	 */
	protected static function formBody(RequestInterface $request): array
	{
		parse_str((string)$request->getBody(), $params);

		/** @var array<string, mixed> $params */
		return $params;
	}

	/**
	 * @return array<string, mixed>
	 */
	protected static function query(string $url): array
	{
		parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

		/** @var array<string, mixed> $query */
		return $query;
	}
}
