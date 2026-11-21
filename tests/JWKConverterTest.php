<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Provider\JWKConverter;
use Vut2\Component\OpenIDConnectClient\Test\Support\TestKeys;

class JWKConverterTest extends TestCase
{
	public function testInvalidKeyIsSkippedWithoutWarning(): void
	{
		// many host applications turn warnings into exceptions
		set_error_handler(static function (int $severity, string $message): bool {
			throw new \ErrorException($message, 0, $severity);
		});

		try {
			$keys = (new JWKConverter())->multipleToPEM([
				TestKeys::rsa()['jwk'],
				['kty' => 'RSA', 'kid' => 'bad', 'n' => 'x', 'e' => 'AQAB'],
			]);
		} finally {
			restore_error_handler();
		}

		self::assertCount(1, $keys);
		self::assertArrayNotHasKey('bad', $keys);
	}
}
