<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * The claim must be present and not empty.
 */
final class NotEmpty implements Constraint
{
	/** @var non-empty-string */
	private string $claimName;

	/**
	 * @param non-empty-string $claimName
	 */
	public function __construct(string $claimName)
	{
		$this->claimName = $claimName;
	}

	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$value = $token->claims()->get($this->claimName);

		if ($value === null || $value === '' || $value === []) {
			throw ConstraintViolation::error(sprintf('Token claim "%s" is missing or empty', $this->claimName), $this);
		}
	}
}
