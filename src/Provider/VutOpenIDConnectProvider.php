<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Provider;

use GuzzleHttp\Client as HttpClient;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Cache\CacheItemPoolInterface;
use Vut2\Component\OpenIDConnectClient\Constraint\AcrIn;
use Vut2\Component\OpenIDConnectClient\Constraint\AuthTimeValid;
use Vut2\Component\OpenIDConnectClient\Constraint\DoesNotHaveClaim;
use Vut2\Component\OpenIDConnectClient\Constraint\HasBackchannelLogoutEvent;
use Vut2\Component\OpenIDConnectClient\Constraint\HasSubOrSid;
use Vut2\Component\OpenIDConnectClient\Constraint\NotEmpty;
use Vut2\Component\OpenIDConnectClient\Constraint\ValidAt;
use Vut2\Component\OpenIDConnectClient\Exception\AuthorizationErrorException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidAuthorizationResponseException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidConfigurationException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Flow\AccessToken;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;
use Vut2\Component\OpenIDConnectClient\Signer\RsaPss;

/**
 * OpenID Connect client for id.vut.cz following OAuth 2.1 recommendations.
 *
 * Flow:
 *  1. getAuthorizationUrl(), store getState(), getPkceCode() and getNonce() in the session
 *  2. validateAuthorizationResponse($_GET, $storedState) returns the authorization code
 *  3. setPkceCode() + setNonce() with stored values, then getAccessToken('authorization_code', ['code' => $code])
 */
class VutOpenIDConnectProvider extends VutProvider
{
	/** Options consumed by the client-side validation, never sent to the token endpoint. */
	private const VALIDATION_OPTIONS = ['nbfToleranceSeconds', 'maxAge', 'requireAuthTime', 'acrValues'];

	private const SIGNERS = [
		'RS256' => Signer\Rsa\Sha256::class,
		'RS384' => Signer\Rsa\Sha384::class,
		'RS512' => Signer\Rsa\Sha512::class,
		'PS256' => RsaPss\Sha256::class,
		'PS384' => RsaPss\Sha384::class,
		'PS512' => RsaPss\Sha512::class,
		'ES256' => Signer\Ecdsa\Sha256::class,
		'ES384' => Signer\Ecdsa\Sha384::class,
		'ES512' => Signer\Ecdsa\Sha512::class,
		'HS256' => Signer\Hmac\Sha256::class,
		'HS384' => Signer\Hmac\Sha384::class,
		'HS512' => Signer\Hmac\Sha512::class,
	];

	protected ?Signer $signer = null;

	/** @var string|array<mixed> PEM key(s) or file:// path(s), indexed by kid when known */
	protected $publicKey;
	protected string $idTokenIssuer;
	protected ?CacheItemPoolInterface $cache = null;

	protected ?string $nonce = null;

	/** @var array<string> */
	protected array $idTokenSigningAlgValues = [];
	protected bool $authorizationResponseIssParameterSupported = false;
	protected bool $validateAudience = true;

	/** @var object|null clock with a now(): DateTimeImmutable method (lcobucci/clock or PSR-20) */
	private ?object $clock = null;

	/** @var array<Key>|null */
	private ?array $keys = null;

	/**
	 * Options (in addition to VutProvider options):
	 *  - issuer: OpenID Provider issuer, used for discovery (default https://id.vut.cz/auth)
	 *  - publicKey + idTokenIssuer: manual configuration without discovery
	 *  - idTokenSigningAlgValues: allowed ID token algorithms (default from discovery, else RS256)
	 *  - authorizationResponseIssParameterSupported: require `iss` in the authorization response (RFC 9207)
	 *  - validateAudience: check that `aud` contains the client_id (default true)
	 *
	 * Collaborators (in addition to VutProvider collaborators):
	 *  - signer: lcobucci/jwt signer that must match the token `alg`
	 *  - cache: PSR-6 cache for discovery and JWKS (1 hour)
	 *  - clock: lcobucci/clock or PSR-20 clock (useful for tests)
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $collaborators
	 * @throws IdentityProviderException
	 */
	public function __construct(array $options = [], array $collaborators = [])
	{
		if (isset($collaborators['signer'])) {
			if (!$collaborators['signer'] instanceof Signer) {
				throw new \InvalidArgumentException(sprintf('Signer must be instance of %s', Signer::class));
			}
			$this->signer = $collaborators['signer'];
		}

		if (isset($collaborators['cache'])) {
			if (!$collaborators['cache'] instanceof CacheItemPoolInterface) {
				throw new \InvalidArgumentException(sprintf('Cache must be instance of %s', CacheItemPoolInterface::class));
			}
			$this->cache = $collaborators['cache'];
		}

		if (isset($collaborators['clock'])) {
			if (!is_object($collaborators['clock']) || !method_exists($collaborators['clock'], 'now')) {
				throw new \InvalidArgumentException('Clock must provide a now() method (lcobucci/clock or PSR-20 clock).');
			}
			$this->clock = $collaborators['clock'];
		}

		if (empty($options['scopes'])) {
			$options['scopes'] = [];
		} elseif (!is_array($options['scopes'])) {
			$options['scopes'] = [$options['scopes']];
		}

		if (!in_array('openid', $options['scopes'], true)) {
			$options['scopes'][] = 'openid';
		}

		if (!isset($options['issuer']) && !isset($options['publicKey'])) {
			$options['issuer'] = self::DEFAULT_ISSUER;
		}

		// Using discovery
		if (isset($options['issuer'])) {
			if (!is_string($options['issuer']) || $options['issuer'] === '') {
				throw new InvalidConfigurationException('Option "issuer" must be a non-empty string.');
			}

			if (empty($collaborators['requestFactory'])) {
				$collaborators['requestFactory'] = new RequestFactory();
			}
			$this->setRequestFactory($collaborators['requestFactory']);

			$collaborators = $this->initPsrHttpClient($collaborators);
			if ($this->getPsrHttpClient() === null) {
				if (empty($collaborators['httpClient'])) {
					$clientOptions = $this->getAllowedClientOptions($options);
					$collaborators['httpClient'] = new HttpClient(array_intersect_key($options, array_flip($clientOptions)));
				}
				$this->setHttpClient($collaborators['httpClient']);
			}

			$options['baseUrl'] = $options['baseUrl'] ?? $options['issuer'];
			$options = $this->discoverConfiguration($options['issuer'], $options);
		}

		if (empty($options['idTokenSigningAlgValues'])) {
			$options['idTokenSigningAlgValues'] = $this->signer !== null ? [$this->signer->algorithmId()] : ['RS256'];
		}
		$options['idTokenSigningAlgValues'] = $this->normalizeAlgorithms($options['idTokenSigningAlgValues']);

		parent::__construct($options, $collaborators);
	}

	/**
	 * Retrieves the nonce sent in the last authorization request.
	 */
	public function getNonce(): ?string
	{
		return $this->nonce;
	}

	/**
	 * Restores the nonce stored in the session before exchanging the authorization code.
	 */
	public function setNonce(?string $nonce): void
	{
		$this->nonce = $nonce;
	}

	/**
	 * Issuer the ID tokens (and the authorization responses) are expected from.
	 */
	public function getIdTokenIssuer(): string
	{
		return $this->idTokenIssuer;
	}

	/**
	 * Whether the authorization server includes `iss` in every authorization response (RFC 9207).
	 */
	public function isAuthorizationResponseIssParameterSupported(): bool
	{
		return $this->authorizationResponseIssParameterSupported;
	}

	/**
	 * Validates the authorization response the user agent was redirected back with and returns the code.
	 *
	 * Checks, in order: `iss` (RFC 9207, mix-up attack protection), `state` (CSRF protection),
	 * error response and the presence of `code`.
	 *
	 * @param array<mixed> $query Query parameters of the redirect URI, typically $_GET
	 * @param string $expectedState State stored in the session before the redirect (getState())
	 *
	 * @throws InvalidAuthorizationResponseException when the response must not be processed
	 * @throws AuthorizationErrorException when the authorization server returned an error
	 */
	public function validateAuthorizationResponse(array $query, string $expectedState): string
	{
		if (array_key_exists('iss', $query)) {
			if (!is_string($query['iss']) || $query['iss'] !== $this->getIdTokenIssuer()) {
				throw new InvalidAuthorizationResponseException('The "iss" parameter of the authorization response does not match the expected issuer.');
			}
		} elseif ($this->authorizationResponseIssParameterSupported) {
			throw new InvalidAuthorizationResponseException('The authorization response is missing the "iss" parameter.');
		}

		$state = $query['state'] ?? null;
		if ($expectedState === '' || !is_string($state) || !hash_equals($expectedState, $state)) {
			throw new InvalidAuthorizationResponseException('Invalid state of the authorization response.');
		}

		if (isset($query['error'])) {
			throw AuthorizationErrorException::fromResponse($query);
		}

		$code = $query['code'] ?? null;
		if (!is_string($code) || $code === '') {
			throw new InvalidAuthorizationResponseException('The authorization response is missing the "code" parameter.');
		}

		return $code;
	}

	/**
	 * Requests an access token using a specified grant and option set.
	 *
	 * For the authorization_code grant the ID token is required and fully validated (signature,
	 * iss, aud, exp/iat/nbf, nonce, azp and optionally acr and auth_time). An ID token returned
	 * by the refresh_token grant is validated as well, without the nonce.
	 *
	 * Validation options (not sent to the server):
	 *  - nbfToleranceSeconds: allowed clock skew in seconds (default 0)
	 *  - maxAge: max_age sent in the authorization request, requires a recent auth_time
	 *  - requireAuthTime: require the auth_time claim
	 *  - acrValues: acr_values sent in the authorization request, the acr claim must be one of them
	 *
	 * @param mixed $grant
	 * @param array<string, mixed> $options
	 * @return AccessTokenInterface
	 * @throws IdentityProviderException
	 * @throws InvalidTokenException
	 */
	public function getAccessToken($grant, array $options = [])
	{
		$validation = array_intersect_key($options, array_flip(self::VALIDATION_OPTIONS));
		$options = array_diff_key($options, $validation);

		$grant = $this->verifyGrant($grant);
		$isAuthorizationCode = $this->isAuthorizationCodeGrant($grant);

		if ($isAuthorizationCode && ($this->nonce === null || $this->nonce === '')) {
			throw new \LogicException(
				'Nonce is missing. Store getNonce() before redirecting the user and restore it with setNonce() before exchanging the code.'
			);
		}

		$accessToken = parent::getAccessToken($grant, $options);

		$idToken = $accessToken instanceof IdToken ? $accessToken->getIdToken() : null;
		if ($idToken !== null) {
			$this->validateIdToken($idToken, $validation, $isAuthorizationCode);
		} elseif ($isAuthorizationCode) {
			throw new InvalidTokenException('Expected an id_token but did not receive one from the authorization server.');
		}

		return $accessToken;
	}

	/**
	 * Parses and validates a back-channel logout token.
	 *
	 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
	 *
	 * @param string $logoutToken Value of the `logout_token` POST parameter
	 * @param array<string, mixed> $options nbfToleranceSeconds: allowed clock skew in seconds
	 * @throws InvalidTokenException
	 */
	public function getLogoutToken(string $logoutToken, array $options = []): Token\Plain
	{
		if ($logoutToken === '') {
			throw new InvalidTokenException('The logout_token is empty.');
		}

		try {
			$token = (new Parser(new JoseEncoder()))->parse($logoutToken);
		} catch (JwtException $e) {
			throw new InvalidTokenException('Unable to parse the logout_token: ' . $e->getMessage(), 0, $e);
		}

		if (!$token instanceof Token\Plain) {
			throw new InvalidTokenException('The logout_token must be a signed (JWS) token.');
		}

		$this->verifySignature($token, 'logout_token');

		$leeway = $this->getLeeway($options);
		$constraints = [
			new IssuedBy($this->nonEmpty($this->getIdTokenIssuer(), 'idTokenIssuer')),
			new ValidAt($this->getClock(), $leeway, false),
			new NotEmpty('jti'),
			new HasSubOrSid(), // A Logout Token MUST contain either a sub or a sid Claim, and MAY contain both.
			new DoesNotHaveClaim('nonce'), // PROHIBITED. A nonce Claim MUST NOT be present.
			new HasBackchannelLogoutEvent(),
		];
		if ($this->validateAudience) {
			$constraints[] = new PermittedFor($this->nonEmpty($this->clientId, 'clientId'));
		}

		$this->assertConstraints($token, $constraints, 'logout_token');

		return $token;
	}

	/**
	 * @inheritDoc
	 */
	public function getResourceOwner(LeagueAccessToken $token)
	{
		if ($token instanceof IdToken && $token->getIdToken() !== null) {
			return $this->createResourceOwner($token->getIdToken()->claims()->all(), $token);
		}

		return parent::getResourceOwner($token);
	}

	/**
	 * Returns all options that are required.
	 *
	 * @return array<string>
	 */
	protected function getRequiredOptions(): array
	{
		$options = parent::getRequiredOptions();
		$options[] = 'publicKey';
		$options[] = 'idTokenIssuer';

		return $options;
	}

	/**
	 * Returns authorization parameters based on provided options.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed> Authorization parameters
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		$this->nonce = isset($options['nonce']) && is_string($options['nonce']) && $options['nonce'] !== ''
			? $options['nonce']
			: $this->getRandomNonce();
		$options['nonce'] = $this->nonce;

		return parent::getAuthorizationParameters($options);
	}

	/**
	 * @param array<string, mixed> $response
	 */
	protected function createAccessToken(array $response, AbstractGrant $grant): AccessTokenInterface
	{
		if (isset($response['id_token'])) {
			return new IdToken($response);
		}

		return new AccessToken($response);
	}

	/**
	 * Validates the claims and the signature of an ID token.
	 *
	 * @param array<string, mixed> $options
	 * @throws InvalidTokenException
	 */
	protected function validateIdToken(Token\Plain $token, array $options, bool $requireNonce): void
	{
		// The Client MUST validate the signature of all ID Tokens according to JWS using the algorithm
		// specified in the JWT alg Header Parameter and the keys provided by the Issuer.
		$this->verifySignature($token, 'id_token');

		// @see http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
		$leeway = $this->getLeeway($options);

		$constraints = [
			new IssuedBy($this->nonEmpty($this->getIdTokenIssuer(), 'idTokenIssuer')),
			new NotEmpty('sub'),
			new ValidAt($this->getClock(), $leeway),
		];

		if ($this->validateAudience) {
			$constraints[] = new PermittedFor($this->nonEmpty($this->clientId, 'clientId'));
		}

		if ($requireNonce) {
			$constraints[] = new HasClaimWithValue('nonce', (string)$this->nonce);
		}

		// If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
		if ($token->claims()->has('azp')) {
			$constraints[] = new HasClaimWithValue('azp', $this->clientId);
		}

		$acrValues = $options['acrValues'] ?? null;
		if (is_string($acrValues)) {
			$acrValues = preg_split('/\s+/', trim($acrValues)) ?: [];
		}
		if (is_array($acrValues) && $acrValues !== []) {
			$constraints[] = new AcrIn(array_values(array_filter($acrValues, 'is_string')));
		}

		$maxAge = isset($options['maxAge']) && is_numeric($options['maxAge']) ? (int)$options['maxAge'] : null;
		$requireAuthTime = !empty($options['requireAuthTime']);
		if ($maxAge !== null || $requireAuthTime) {
			$constraints[] = new AuthTimeValid($this->getClock(), $maxAge, $leeway, $requireAuthTime);
		}

		$this->assertConstraints($token, $constraints, 'id_token');
	}

	/**
	 * Verifies the token signature with an allowed algorithm and the issuer keys.
	 *
	 * Asymmetric algorithms are verified with the issuer public keys only, HMAC algorithms with the
	 * client secret only, so a public key can never be abused as an HMAC secret.
	 *
	 * @throws InvalidTokenException
	 */
	protected function verifySignature(Token\Plain $token, string $tokenName): void
	{
		$alg = $token->headers()->get('alg');
		if (!is_string($alg) || $alg === '' || strtolower($alg) === 'none') {
			throw new InvalidTokenException(sprintf('The %s must be signed.', $tokenName));
		}

		if (!in_array($alg, $this->idTokenSigningAlgValues, true)) {
			throw new InvalidTokenException(sprintf('The %s is signed with a disallowed algorithm "%s".', $tokenName, $alg));
		}

		$signer = $this->getSignerForAlgorithm($alg);
		if ($signer === null) {
			throw new InvalidTokenException(sprintf('The %s is signed with an unsupported algorithm "%s".', $tokenName, $alg));
		}

		foreach ($this->getVerificationKeys($token, $alg) as $key) {
			if ($this->isSignedWith($token, $signer, $key)) {
				return;
			}
		}

		throw new InvalidTokenException(sprintf('Received an invalid %s from authorization server.', $tokenName));
	}

	/**
	 * Retrieves OpenID Connect configuration from a discovery endpoint
	 * (<$issuer>/.well-known/openid-configuration) and merges it into
	 * a given options array. Explicitly given options take precedence.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>
	 * @throws InvalidConfigurationException
	 * @throws IdentityProviderException
	 */
	protected function discoverConfiguration(string $issuer, array $options): array
	{
		$uri = rtrim($issuer, '/') . '/.well-known/openid-configuration';
		$response = $this->fetchJson($uri);

		// OpenID Connect Discovery 1.0 §4.3: the issuer value MUST be identical to the configured issuer
		if (!isset($response['issuer']) || $response['issuer'] !== $issuer) {
			throw new InvalidConfigurationException(sprintf(
				'Issuer "%s" in discovery configuration at %s does not match the configured issuer "%s".',
				is_string($response['issuer'] ?? null) ? $response['issuer'] : '',
				$uri,
				$issuer
			));
		}

		// Map configuration to options
		$optionMapping = [
			'idTokenIssuer' => ['name' => 'issuer', 'required' => true],
			'urlAuthorize' => ['name' => 'authorization_endpoint', 'required' => true],
			'urlAccessToken' => ['name' => 'token_endpoint', 'required' => true],
			'urlResourceOwnerDetails' => ['name' => 'userinfo_endpoint', 'required' => false],
			'urlEndSession' => ['name' => 'end_session_endpoint', 'required' => false],
			'urlRevokeToken' => ['name' => 'revocation_endpoint', 'required' => false],
			'idTokenSigningAlgValues' => ['name' => 'id_token_signing_alg_values_supported', 'required' => false],
			'authorizationResponseIssParameterSupported' => ['name' => 'authorization_response_iss_parameter_supported', 'required' => false],
		];

		foreach ($optionMapping as $optionKey => $responseKey) {
			if (!isset($response[$responseKey['name']])) {
				if ($responseKey['required']) {
					throw new InvalidConfigurationException(
						"Required parameter {$responseKey['name']} missing in discovery configuration at $uri"
					);
				}
				continue;
			}

			$options[$optionKey] = $options[$optionKey] ?? $response[$responseKey['name']];
		}

		// OAuth 2.1 requires PKCE with S256
		if (isset($response['code_challenge_methods_supported'])
			&& (!is_array($response['code_challenge_methods_supported'])
				|| !in_array(self::PKCE_METHOD_S256, $response['code_challenge_methods_supported'], true))
		) {
			throw new InvalidConfigurationException("The authorization server at $uri does not support PKCE with S256.");
		}

		$options['tokenEndpointAuthMethod'] = $this->resolveTokenEndpointAuthMethod(
			$options['tokenEndpointAuthMethod'] ?? null,
			$response['token_endpoint_auth_methods_supported'] ?? null,
			$uri
		);

		if (!isset($response['jwks_uri']) || !is_string($response['jwks_uri'])) {
			throw new InvalidConfigurationException("Required parameter jwks_uri missing in discovery configuration at $uri");
		}

		if (!isset($options['publicKey'])) {
			$allowedAlgorithms = isset($options['idTokenSigningAlgValues'])
				? $this->normalizeAlgorithms($options['idTokenSigningAlgValues'])
				: [];
			$options['publicKey'] = $this->fetchPublicKeys($response['jwks_uri'], $allowedAlgorithms, $uri);
		}

		return $options;
	}

	/**
	 * Returns a new random string to use as nonce.
	 *
	 * @param int $length Length of the random string to be generated.
	 */
	protected function getRandomNonce(int $length = 64): string
	{
		return substr(
			strtr(
				base64_encode(random_bytes(max(1, $length))),
				'+/',
				'-_'
			),
			0,
			$length
		);
	}

	/**
	 * @param array<Constraint> $constraints
	 * @throws InvalidTokenException
	 */
	private function assertConstraints(Token\Plain $token, array $constraints, string $tokenName): void
	{
		try {
			foreach ($constraints as $constraint) {
				$constraint->assert($token);
			}
		} catch (ConstraintViolation $e) {
			throw new InvalidTokenException(sprintf('The %s did not pass validation. %s', $tokenName, $e->getMessage()), 0, $e);
		}
	}

	private function getSignerForAlgorithm(string $alg): ?Signer
	{
		if ($this->signer !== null) {
			if ($this->signer->algorithmId() !== $alg) {
				return null;
			}

			return $this->signer;
		}

		if (!isset(self::SIGNERS[$alg])) {
			return null;
		}

		$class = self::SIGNERS[$alg];

		return new $class();
	}

	/**
	 * @return array<Key>
	 */
	private function getVerificationKeys(Token\Plain $token, string $alg): array
	{
		if (strpos($alg, 'HS') === 0) {
			// OIDC Core §10.1: symmetric signatures use the octets of the client_secret as the key
			return [InMemory::plainText($this->nonEmpty($this->clientSecret, 'clientSecret'))];
		}

		$keys = $this->getPublicKeys();
		$kid = $token->headers()->get('kid');
		if (is_string($kid) && $kid !== '' && isset($keys[$kid])) {
			return [$keys[$kid]];
		}

		return array_values($keys);
	}

	private function isSignedWith(Token\Plain $token, Signer $signer, Key $key): bool
	{
		try {
			return (new Validator())->validate($token, new SignedWith($signer, $key));
		} catch (\InvalidArgumentException $e) {
			// incompatible or invalid key (e.g. EC key for an RSA signature, HMAC secret too short)
			return false;
		}
	}

	/**
	 * @return array<Key>
	 */
	private function getPublicKeys(): array
	{
		if ($this->keys === null) {
			$publicKeys = is_array($this->publicKey) ? $this->publicKey : [$this->publicKey];
			$keys = [];
			foreach ($publicKeys as $id => $content) {
				if (!is_string($content) || $content === '') {
					continue;
				}
				$path = strpos($content, 'file://') === 0 ? substr($content, 7) : '';
				$keys[$id] = $path !== ''
					? InMemory::file($path)
					: InMemory::plainText($content);
			}
			$this->keys = $keys;
		}

		return $this->keys;
	}

	/**
	 * @param array<string> $allowedAlgorithms
	 * @return array<string> PEM keys indexed by kid when present
	 * @throws InvalidConfigurationException
	 * @throws IdentityProviderException
	 */
	private function fetchPublicKeys(string $jwksUri, array $allowedAlgorithms, string $discoveryUri): array
	{
		$cache = $this->cache;
		$cacheItem = $cache !== null ? $cache->getItem(hash('sha256', self::class . '_pem_' . $jwksUri)) : null;
		if ($cacheItem !== null && $cacheItem->isHit() && is_array($cacheItem->get()) && $cacheItem->get() !== []) {
			/** @var array<string> $cached */
			$cached = $cacheItem->get();

			return $cached;
		}

		$jwksResponse = $this->fetchJson($jwksUri, false);
		if (!isset($jwksResponse['keys']) || !is_array($jwksResponse['keys'])) {
			throw new InvalidConfigurationException("Invalid JWKS received from $jwksUri. Expected JSON with keys.");
		}

		$signer = $this->signer;
		// We only need signature keys usable with the allowed algorithms
		$jwks = array_filter($jwksResponse['keys'], static function ($jwk) use ($allowedAlgorithms, $signer): bool {
			if (!is_array($jwk)) {
				return false;
			}
			if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
				return false;
			}
			if (isset($jwk['alg'])) {
				if ($signer !== null && $jwk['alg'] !== $signer->algorithmId()) {
					return false;
				}
				if ($allowedAlgorithms !== [] && !in_array($jwk['alg'], $allowedAlgorithms, true)) {
					return false;
				}
			}

			return true;
		});

		$keys = $jwks === [] ? [] : (new JWKConverter())->multipleToPEM($jwks);
		if ($keys === []) {
			throw new InvalidConfigurationException("No valid signing keys found in discovery at $discoveryUri");
		}

		if ($cache !== null && $cacheItem !== null) {
			$cacheItem->set($keys);
			$cacheItem->expiresAfter(3600);
			$cache->save($cacheItem);
		}

		return $keys;
	}

	/**
	 * @return array<mixed>
	 * @throws InvalidConfigurationException
	 * @throws IdentityProviderException
	 */
	private function fetchJson(string $uri, bool $useCache = true): array
	{
		$cache = $useCache ? $this->cache : null;
		$cacheItem = $cache !== null ? $cache->getItem(hash('sha256', self::class . '_' . $uri)) : null;
		if ($cacheItem !== null && $cacheItem->isHit() && is_array($cacheItem->get())) {
			/** @var array<mixed> $cached */
			$cached = $cacheItem->get();

			return $cached;
		}

		$response = $this->getParsedResponse($this->getRequest(self::METHOD_GET, $uri));
		if (!is_array($response)) {
			throw new InvalidConfigurationException("Invalid response received from $uri. Expected JSON.");
		}

		if ($cache !== null && $cacheItem !== null) {
			$cacheItem->set($response);
			$cacheItem->expiresAfter(3600);
			$cache->save($cacheItem);
		}

		return $response;
	}

	/**
	 * @param mixed $configured
	 * @param mixed $supported
	 */
	private function resolveTokenEndpointAuthMethod($configured, $supported, string $uri): string
	{
		$advertised = is_array($supported);
		// RFC 8414 §2: if omitted, the default is client_secret_basic
		$supported = is_array($supported) ? $supported : [self::AUTH_METHOD_CLIENT_SECRET_BASIC];

		if ($configured !== null) {
			// An explicit choice is only checked against a list the server actually publishes
			if (!is_string($configured) || ($advertised && !in_array($configured, $supported, true))) {
				throw new InvalidConfigurationException(sprintf(
					'Token endpoint auth method "%s" is not supported by the authorization server at %s.',
					is_string($configured) ? $configured : gettype($configured),
					$uri
				));
			}

			return $configured;
		}

		foreach ([self::AUTH_METHOD_CLIENT_SECRET_BASIC, self::AUTH_METHOD_CLIENT_SECRET_POST] as $method) {
			if (in_array($method, $supported, true)) {
				return $method;
			}
		}

		throw new InvalidConfigurationException(
			"The authorization server at $uri supports neither client_secret_basic nor client_secret_post."
		);
	}

	/**
	 * @param mixed $algorithms
	 * @return array<string>
	 */
	private function normalizeAlgorithms($algorithms): array
	{
		if (is_string($algorithms)) {
			$algorithms = [$algorithms];
		}
		if (!is_array($algorithms)) {
			throw new InvalidConfigurationException('idTokenSigningAlgValues must be a list of algorithms.');
		}

		$result = [];
		foreach ($algorithms as $algorithm) {
			if (is_string($algorithm) && $algorithm !== '' && strtolower($algorithm) !== 'none') {
				$result[] = $algorithm;
			}
		}

		if ($result === []) {
			throw new InvalidConfigurationException('No usable ID token signing algorithm is configured.');
		}

		return array_values(array_unique($result));
	}

	/**
	 * @param array<string, mixed> $options
	 */
	private function getLeeway(array $options): int
	{
		$leeway = $options['nbfToleranceSeconds'] ?? 0;

		return is_int($leeway) && $leeway > 0 ? $leeway : 0;
	}

	/**
	 * @return non-empty-string
	 */
	private function nonEmpty(string $value, string $name): string
	{
		if ($value === '') {
			throw new InvalidConfigurationException(sprintf('Option "%s" must not be empty.', $name));
		}

		return $value;
	}

	private function getClock(): object
	{
		if ($this->clock === null) {
			$this->clock = SystemClock::fromUTC();
		}

		return $this->clock;
	}
}
