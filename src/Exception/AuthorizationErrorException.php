<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Exception;

/**
 * The authorization server redirected back with an error (RFC 6749 §4.1.2.1).
 */
final class AuthorizationErrorException extends \RuntimeException
{
	public const UNMET_AUTHENTICATION_REQUIREMENTS = 'unmet_authentication_requirements';
	public const LOGIN_REQUIRED = 'login_required';
	public const ACCESS_DENIED = 'access_denied';

	private string $error;
	private ?string $errorDescription;
	private ?string $errorUri;

	public function __construct(string $error, ?string $errorDescription = null, ?string $errorUri = null)
	{
		$this->error = $error;
		$this->errorDescription = $errorDescription;
		$this->errorUri = $errorUri;

		parent::__construct(
			$errorDescription !== null && $errorDescription !== ''
				? sprintf('Authorization failed: %s (%s)', $error, $errorDescription)
				: sprintf('Authorization failed: %s', $error)
		);
	}

	/**
	 * @param array<mixed> $query Query parameters of the authorization response
	 */
	public static function fromResponse(array $query): self
	{
		$error = $query['error'] ?? null;
		$description = $query['error_description'] ?? null;
		$uri = $query['error_uri'] ?? null;

		return new self(
			is_string($error) ? $error : 'unknown_error',
			is_string($description) ? $description : null,
			is_string($uri) ? $uri : null
		);
	}

	/**
	 * Error code, e.g. `access_denied`, `login_required`, `unmet_authentication_requirements`.
	 */
	public function getError(): string
	{
		return $this->error;
	}

	public function getErrorDescription(): ?string
	{
		return $this->errorDescription;
	}

	public function getErrorUri(): ?string
	{
		return $this->errorUri;
	}

	/**
	 * The requested `acr_values` could not be satisfied.
	 *
	 * @see https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html
	 */
	public function isUnmetAuthenticationRequirements(): bool
	{
		return $this->error === self::UNMET_AUTHENTICATION_REQUIREMENTS;
	}
}
