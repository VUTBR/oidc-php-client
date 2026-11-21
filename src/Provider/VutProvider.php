<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Provider;

use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Exception\BadResponseException;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Client\ClientInterface as PsrClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidConfigurationException;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\OptionProvider\ClientSecretBasicOptionProvider;
use Vut2\Component\OpenIDConnectClient\OptionProvider\ClientSecretPostOptionProvider;
use Vut2\Component\OpenIDConnectClient\Tool\QueryString;

/**
 * OAuth 2.1 client for id.vut.cz (confidential clients only).
 *
 * - PKCE with S256 is always used.
 * - The client authenticates with `client_secret_basic` (default) or `client_secret_post`.
 * - Any PSR-18 HTTP client can be used instead of Guzzle.
 */
class VutProvider extends GenericProvider
{
	use BearerAuthorizationTrait;

	public const DEFAULT_ISSUER = 'https://id.vut.cz/auth';

	public const AUTH_METHOD_CLIENT_SECRET_BASIC = 'client_secret_basic';
	public const AUTH_METHOD_CLIENT_SECRET_POST = 'client_secret_post';

	protected string $baseUrl = self::DEFAULT_ISSUER;

	/**
	 * @var string|null If set, this will be sent as the "prompt" parameter.
	 */
	protected $prompt;

	/**
	 * @var array<string> List of scopes that will be used for authentication.
	 */
	protected $scopes = [];

	protected ?string $urlEndSession = null;
	protected ?string $urlRevokeToken = null;
	protected ?string $tokenEndpointAuthMethod = null;

	private ?PsrClientInterface $psrHttpClient = null;

	/**
	 * Options (in addition to league/oauth2-client GenericProvider options):
	 *  - clientId, clientSecret, redirectUri (required)
	 *  - baseUrl: base used for default endpoint URLs (default https://id.vut.cz/auth)
	 *  - tokenEndpointAuthMethod: client_secret_basic (default) | client_secret_post
	 *  - urlEndSession, urlRevokeToken
	 *
	 * Collaborators: httpClient (Guzzle or any PSR-18 client), requestFactory, grantFactory, optionProvider.
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $collaborators
	 */
	public function __construct(array $options = [], array $collaborators = [])
	{
		if (empty($options['clientId']) || !is_string($options['clientId'])) {
			throw new InvalidConfigurationException('Option "clientId" is required.');
		}
		if (empty($options['clientSecret']) || !is_string($options['clientSecret'])) {
			throw new InvalidConfigurationException('Option "clientSecret" is required, only confidential clients are supported.');
		}

		$baseUrl = isset($options['baseUrl']) && is_string($options['baseUrl']) ? rtrim($options['baseUrl'], '/') : $this->baseUrl;
		$options['baseUrl'] = $baseUrl;
		$options += [
			'urlAuthorize' => null,
			'urlAccessToken' => null,
			'urlResourceOwnerDetails' => null,
			'urlEndSession' => null,
			'urlRevokeToken' => null,
		];
		$options['urlAuthorize'] = $options['urlAuthorize'] ?: $baseUrl . '/common/oauth2/authorize';
		$options['urlAccessToken'] = $options['urlAccessToken'] ?: $baseUrl . '/common/oauth2/token';
		$options['urlResourceOwnerDetails'] = $options['urlResourceOwnerDetails'] ?: $baseUrl . '/oidc/userinfo';
		$options['urlEndSession'] = $options['urlEndSession'] ?: $baseUrl . '/common/oauth2/endSession';
		$options['urlRevokeToken'] = $options['urlRevokeToken'] ?: $baseUrl . '/common/oauth2/revoke';

		// OAuth 2.1: PKCE is mandatory and only S256 is allowed.
		if (!empty($options['pkceMethod']) && $options['pkceMethod'] !== self::PKCE_METHOD_S256) {
			throw new InvalidConfigurationException('Only the S256 PKCE method is supported.');
		}
		$options['pkceMethod'] = self::PKCE_METHOD_S256;

		$authMethod = $options['tokenEndpointAuthMethod'] ?? self::AUTH_METHOD_CLIENT_SECRET_BASIC;
		if (!in_array($authMethod, [self::AUTH_METHOD_CLIENT_SECRET_BASIC, self::AUTH_METHOD_CLIENT_SECRET_POST], true)) {
			throw new InvalidConfigurationException(sprintf(
				'Unsupported tokenEndpointAuthMethod "%s", use "%s" or "%s".',
				is_scalar($authMethod) ? (string)$authMethod : gettype($authMethod),
				self::AUTH_METHOD_CLIENT_SECRET_BASIC,
				self::AUTH_METHOD_CLIENT_SECRET_POST
			));
		}
		$options['tokenEndpointAuthMethod'] = $authMethod;

		if (empty($collaborators['optionProvider'])) {
			$collaborators['optionProvider'] = $authMethod === self::AUTH_METHOD_CLIENT_SECRET_POST
				? new ClientSecretPostOptionProvider()
				: new ClientSecretBasicOptionProvider();
		}

		$collaborators = $this->initPsrHttpClient($collaborators);

		parent::__construct($options, $collaborators);
	}

	/**
	 * Use a PSR-18 HTTP client (e.g. Symfony's Psr18Client) for all requests.
	 * Pass null to switch back to the Guzzle client.
	 */
	public function setPsrHttpClient(?PsrClientInterface $client): self
	{
		$this->psrHttpClient = $client;

		return $this;
	}

	public function getPsrHttpClient(): ?PsrClientInterface
	{
		return $this->psrHttpClient;
	}

	public function getTokenEndpointAuthMethod(): string
	{
		return $this->tokenEndpointAuthMethod ?? self::AUTH_METHOD_CLIENT_SECRET_BASIC;
	}

	/**
	 * Sends a request using the PSR-18 client if one was provided, Guzzle otherwise.
	 */
	public function getResponse(RequestInterface $request): ResponseInterface
	{
		if ($this->psrHttpClient !== null) {
			return $this->psrHttpClient->sendRequest($request);
		}

		return parent::getResponse($request);
	}

	/**
	 * Requests an access token using a specified grant and option set.
	 *
	 * @param mixed $grant
	 * @param array<string, mixed> $options
	 * @return AccessTokenInterface
	 * @throws IdentityProviderException
	 */
	public function getAccessToken($grant, array $options = [])
	{
		$grant = $this->verifyGrant($grant);

		// league/oauth2-client < 2.8 does not join a scope list; it must be one space-delimited parameter
		if (isset($options['scope']) && is_array($options['scope'])) {
			$options['scope'] = implode($this->getScopeSeparator(), $options['scope']);
		}

		$isAuthorizationCode = $this->isAuthorizationCodeGrant($grant);
		if ($isAuthorizationCode && empty($this->pkceCode)) {
			throw new \LogicException(
				'PKCE code verifier is missing. Store getPkceCode() before redirecting the user and restore it with setPkceCode() before exchanging the code.'
			);
		}

		// code_verifier belongs to the authorization code exchange only
		$pkceCode = $this->pkceCode;
		if (!$isAuthorizationCode) {
			$this->pkceCode = null;
		}

		try {
			return parent::getAccessToken($grant, $options);
		} finally {
			$this->pkceCode = $pkceCode;
		}
	}

	/**
	 * Get revoke token url to revoke token
	 *
	 * @param array<string, mixed> $params
	 */
	public function getBaseRevokeTokenUrl(array $params): ?string
	{
		return $this->urlRevokeToken;
	}

	/**
	 * Revokes an access or refresh token (RFC 7009).
	 *
	 * @param string $token Access or refresh token
	 * @param string|null $tokenTypeHint `access_token` or `refresh_token`
	 * @throws IdentityProviderException
	 */
	public function revokeAccessToken(string $token, ?string $tokenTypeHint = null): ResponseInterface
	{
		$url = $this->getBaseRevokeTokenUrl([]);
		if ($url === null || $url === '') {
			throw new InvalidConfigurationException('Missing revocation endpoint (urlRevokeToken).');
		}

		$params = [
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'token' => $token,
		];
		if ($tokenTypeHint !== null) {
			$params['token_type_hint'] = $tokenTypeHint;
		}

		$method = self::METHOD_POST;
		$options = $this->optionProvider->getAccessTokenOptions($method, $params);
		$request = $this->getRequest($method, $url, $options);

		return $this->getRevokeResponse($request);
	}

	/**
	 * Sends a revocation request and checks the status code.
	 *
	 * @throws IdentityProviderException
	 */
	public function getRevokeResponse(RequestInterface $request): ResponseInterface
	{
		try {
			$response = $this->getResponse($request);
		} catch (BadResponseException $e) {
			$response = $e->getResponse();
		}

		if ($response->getStatusCode() !== 200) {
			throw new IdentityProviderException('Invalid status code', $response->getStatusCode(), (string)$response->getBody());
		}

		return $response;
	}

	/**
	 * URL for RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0).
	 *
	 * Supported parameters: id_token_hint (string or token object), post_logout_redirect_uri,
	 * state, ui_locales, logout_hint.
	 *
	 * @param array<string, mixed> $params
	 */
	public function getLogoutUrl(array $params = []): string
	{
		if ($this->urlEndSession === null || $this->urlEndSession === '') {
			throw new \InvalidArgumentException('Missing end session url');
		}

		$parts = explode('?', $this->urlEndSession, 2);
		$query = [];
		if (isset($parts[1])) {
			parse_str($parts[1], $query);
		}

		$query['client_id'] = $this->clientId;

		if (isset($params['id_token_hint']) && is_object($params['id_token_hint']) && method_exists($params['id_token_hint'], 'toString')) {
			$params['id_token_hint'] = $params['id_token_hint']->toString();
		}

		foreach (['id_token_hint', 'post_logout_redirect_uri', 'state', 'ui_locales', 'logout_hint'] as $name) {
			if (isset($params[$name]) && is_string($params[$name]) && $params[$name] !== '') {
				$query[$name] = $params[$name];
			}
		}

		return $parts[0] . '?' . QueryString::build($query);
	}

	/**
	 * Returns authorization parameters based on provided options.
	 *
	 * Additional options: prompt, max_age, acr_values (string or list), resource (string or list, RFC 8707).
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed> Authorization parameters
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		if (empty($options['prompt']) && $this->prompt) {
			$options['prompt'] = $this->prompt;
		}

		// Default scopes MUST be included for OpenID Connect.
		// Additional scopes MAY be added by constructor or option.
		$scopes = array_merge((array)$this->getDefaultScopes(), $this->scopes);

		if (!empty($options['scope'])) {
			$scopes = array_merge($scopes, is_array($options['scope']) ? $options['scope'] : explode(' ', (string)$options['scope']));
		}

		$options['scope'] = array_values(array_unique($scopes));

		if (isset($options['acr_values']) && is_array($options['acr_values'])) {
			$options['acr_values'] = implode(' ', $options['acr_values']);
		}

		$options = parent::getAuthorizationParameters($options);

		// Not part of OAuth 2.1 / OpenID Connect
		unset($options['approval_prompt']);

		return $options;
	}

	/**
	 * @param array<string, mixed> $params
	 */
	protected function getAuthorizationQuery(array $params): string
	{
		return QueryString::build($params);
	}

	protected function getScopeSeparator(): string
	{
		return ' ';
	}

	/**
	 * @param array<string, mixed> $response
	 */
	protected function createAccessToken(array $response, AbstractGrant $grant): AccessTokenInterface
	{
		return new AccessToken($response);
	}

	/**
	 * Create a resource owner object based on the given response and access token.
	 *
	 * @param array<string, mixed> $response The response from the OAuth server.
	 * @param LeagueAccessToken $token The access token.
	 * @return VutUser The created resource owner object.
	 */
	protected function createResourceOwner(array $response, LeagueAccessToken $token): VutUser
	{
		return new VutUser($response);
	}

	protected function isAuthorizationCodeGrant(AbstractGrant $grant): bool
	{
		return (string)$grant === 'authorization_code';
	}

	/**
	 * Separates a PSR-18 client from the collaborators, league/oauth2-client itself only accepts Guzzle.
	 *
	 * @param array<string, mixed> $collaborators
	 * @return array<string, mixed>
	 */
	protected function initPsrHttpClient(array $collaborators): array
	{
		$client = $collaborators['httpClient'] ?? null;
		if ($client === null || $client instanceof GuzzleClientInterface) {
			return $collaborators;
		}

		if (!$client instanceof PsrClientInterface) {
			throw new \InvalidArgumentException(sprintf(
				'httpClient must implement %s or %s',
				GuzzleClientInterface::class,
				PsrClientInterface::class
			));
		}

		$this->psrHttpClient = $client;
		unset($collaborators['httpClient']);

		return $collaborators;
	}
}
