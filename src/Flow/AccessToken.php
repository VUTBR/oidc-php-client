<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Flow;

use League\OAuth2\Client\Token\AccessToken as LeagueAccessToken;

/**
 * Access token returned by the token endpoint, with helpers for the fields sent by id.vut.cz.
 */
class AccessToken extends LeagueAccessToken
{
	private ?int $refreshExpires = null;

	/**
	 * @param array<string, mixed> $options Token endpoint response, or the result of jsonSerialize()
	 */
	public function __construct(array $options = [])
	{
		parent::__construct($options);

		// Like expires_in → expires in league: keep the refresh token expiration as a timestamp
		if (isset($options['refresh_expires_in']) && is_numeric($options['refresh_expires_in'])) {
			$this->refreshExpires = $this->getTimeNow() + (int)$options['refresh_expires_in'];
		} elseif (isset($options['refresh_expires']) && is_numeric($options['refresh_expires'])) {
			$this->refreshExpires = (int)$options['refresh_expires'];
		}

		unset($this->values['refresh_expires_in'], $this->values['refresh_expires']);
	}

	/**
	 * Scopes from the space-delimited `scope` parameter (legacy id.vut.cz: `scopes`).
	 *
	 * Per RFC 6749 §5.1 a missing or empty scope means the scope is identical to the requested one;
	 * an empty array is returned in that case.
	 *
	 * @return array<string>
	 */
	public function getScopes(): array
	{
		$scope = $this->values['scope'] ?? $this->values['scopes'] ?? '';

		return is_string($scope) ? (preg_split('/\s+/', $scope, -1, PREG_SPLIT_NO_EMPTY) ?: []) : [];
	}

	/**
	 * Refresh token expiration as a Unix timestamp (`refresh_expires_in`), null when not provided.
	 */
	public function getRefreshTokenExpires(): ?int
	{
		return $this->refreshExpires;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		/** @var array<string, mixed> $parameters */
		$parameters = parent::jsonSerialize();

		if ($this->refreshExpires !== null) {
			$parameters['refresh_expires'] = $this->refreshExpires;
		}

		return $parameters;
	}
}
