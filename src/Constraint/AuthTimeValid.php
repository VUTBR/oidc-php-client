<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * Validates the `auth_time` claim against the requested `max_age` (OIDC Core §3.1.3.7, point 11).
 */
final class AuthTimeValid implements Constraint
{
	private \Closure $now;
	private ?int $maxAge;
	private int $leeway;
	private bool $required;

	public function __construct(object $clock, ?int $maxAge, int $leeway = 0, bool $required = true)
	{
		if (!method_exists($clock, 'now')) {
			throw new \InvalidArgumentException('Clock must provide a now() method.');
		}
		if ($maxAge !== null && $maxAge < 0) {
			throw new \InvalidArgumentException('max_age must not be negative.');
		}

		$this->now = \Closure::fromCallable([$clock, 'now']);
		$this->maxAge = $maxAge;
		$this->leeway = max(0, $leeway);
		$this->required = $required || $maxAge !== null;
	}

	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$authTime = $token->claims()->get('auth_time');
		if ($authTime === null) {
			if ($this->required) {
				throw ConstraintViolation::error('The token is missing the "auth_time" claim', $this);
			}

			return;
		}

		if ($authTime instanceof \DateTimeInterface) {
			$authTime = $authTime->getTimestamp();
		} elseif (is_numeric($authTime)) {
			$authTime = (int)$authTime;
		} else {
			throw ConstraintViolation::error('The "auth_time" claim must be a number', $this);
		}

		$now = ($this->now)();
		if (!$now instanceof \DateTimeImmutable) {
			throw ConstraintViolation::error('The clock must return a DateTimeImmutable', $this);
		}
		$now = $now->getTimestamp();

		if ($authTime > $now + $this->leeway) {
			throw ConstraintViolation::error('The "auth_time" claim is in the future', $this);
		}

		if ($this->maxAge !== null && $authTime + $this->maxAge + $this->leeway < $now) {
			throw ConstraintViolation::error('The end-user authenticated too long ago (max_age exceeded)', $this);
		}
	}
}
