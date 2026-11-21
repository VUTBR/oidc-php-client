<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Signer\RsaPss;
use Vut2\Component\OpenIDConnectClient\Test\Support\TestKeys;

class RsaPssTest extends TestCase
{
	public function testSignAndVerifyRoundTrip(): void
	{
		$keys = TestKeys::rsa();
		$signers = [new RsaPss\Sha256(), new RsaPss\Sha384(), new RsaPss\Sha512()];

		foreach ($signers as $signer) {
			$signature = $signer->sign('payload', InMemory::plainText($keys['private']));

			self::assertTrue($signer->verify($signature, 'payload', InMemory::plainText($keys['public'])), $signer->algorithmId());
			self::assertFalse($signer->verify($signature, 'tampered', InMemory::plainText($keys['public'])), $signer->algorithmId());
		}
	}
}
