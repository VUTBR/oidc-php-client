<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * The `acr` claim must be one of the requested `acr_values`.
 */
final class AcrIn implements Constraint
{
	/** @var array<string> */
	private array $allowed;

	/**
	 * @param array<string> $allowed
	 */
	public function __construct(array $allowed)
	{
		$this->allowed = array_values($allowed);
	}

	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$acr = $token->claims()->get('acr');
		if (!is_string($acr) || !in_array($acr, $this->allowed, true)) {
			throw ConstraintViolation::error(
				sprintf('The "acr" claim must be one of: %s', implode(', ', $this->allowed)),
				$this
			);
		}
	}
}
