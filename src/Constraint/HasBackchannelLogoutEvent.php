<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * The `events` claim of a logout token must be a JSON object containing the member
 * `http://schemas.openid.net/event/backchannel-logout` whose value is a JSON object.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
 */
final class HasBackchannelLogoutEvent implements Constraint
{
	public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$events = $token->claims()->get('events');
		if (!is_array($events) || !array_key_exists(self::EVENT, $events) || !is_array($events[self::EVENT])) {
			throw ConstraintViolation::error('The token must contain the back-channel logout event in the "events" claim', $this);
		}
	}
}
