<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Exception;

/**
 * An ID token or logout token failed signature or claim validation.
 */
final class InvalidTokenException extends \RuntimeException
{
}
