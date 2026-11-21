<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * Time validation of a token that works the same with lcobucci/jwt 4 and 5.
 *
 * - `iat` is required and must not be in the future
 * - `exp` is required (unless disabled) and must not have passed
 * - without `exp`, `iat` must not be older than the optional max age
 * - `nbf` is checked when present
 */
final class ValidAt implements Constraint
{
	private \Closure $now;
	private \DateInterval $leeway;
	private bool $requireExpiration;
	private ?int $maxAgeWithoutExpiration;

	public function __construct(object $clock, int $leewaySeconds = 0, bool $requireExpiration = true, ?int $maxAgeWithoutExpiration = null)
	{
		if (!method_exists($clock, 'now')) {
			throw new \InvalidArgumentException('Clock must provide a now() method.');
		}

		$this->now = \Closure::fromCallable([$clock, 'now']);
		$this->leeway = new \DateInterval('PT' . max(0, $leewaySeconds) . 'S');
		$this->requireExpiration = $requireExpiration;
		$this->maxAgeWithoutExpiration = $maxAgeWithoutExpiration;
	}

	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$now = ($this->now)();
		if (!$now instanceof \DateTimeImmutable) {
			throw ConstraintViolation::error('The clock must return a DateTimeImmutable', $this);
		}
		$claims = $token->claims();

		if (!$claims->has(RegisteredClaims::ISSUED_AT)) {
			throw ConstraintViolation::error('"Issued At" claim missing', $this);
		}
		if (!$token->hasBeenIssuedBefore($now->add($this->leeway))) {
			throw ConstraintViolation::error('The token was issued in the future', $this);
		}

		if ($claims->has(RegisteredClaims::NOT_BEFORE) && !$token->isMinimumTimeBefore($now->add($this->leeway))) {
			throw ConstraintViolation::error('The token cannot be used yet', $this);
		}

		if (!$claims->has(RegisteredClaims::EXPIRATION_TIME)) {
			if ($this->requireExpiration) {
				throw ConstraintViolation::error('"Expiration Time" claim missing', $this);
			}

			$issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
			if ($this->maxAgeWithoutExpiration !== null && $issuedAt instanceof \DateTimeImmutable
				&& $issuedAt->getTimestamp() + $this->maxAgeWithoutExpiration < $now->sub($this->leeway)->getTimestamp()
			) {
				throw ConstraintViolation::error('The token is too old', $this);
			}

			return;
		}

		if ($token->isExpired($now->sub($this->leeway))) {
			throw ConstraintViolation::error('The token is expired', $this);
		}
	}
}
