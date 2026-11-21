<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Exception;

/**
 * The authorization response failed validation (state or iss mismatch, missing code).
 * Such a response must not be processed any further.
 */
final class InvalidAuthorizationResponseException extends \RuntimeException
{
}
