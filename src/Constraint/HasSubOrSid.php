<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * A logout token must contain either a `sub` or a `sid` claim, and may contain both.
 */
final class HasSubOrSid implements Constraint
{
	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$claims = $token->claims();
		$sub = $claims->get('sub');
		$sid = $claims->get('sid');

		if (($sub === null || $sub === '') && ($sid === null || $sid === '')) {
			throw ConstraintViolation::error('The logout token must contain either a "sub" or "sid" claim.', $this);
		}
	}
}
