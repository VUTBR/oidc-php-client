<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Signer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Vut2\Component\OpenIDConnectClient\Crypto\Phpseclib;

/**
 * RSASSA-PSS signer (PS256/PS384/PS512), which lcobucci/jwt does not provide.
 */
abstract class RsaPss implements Signer
{
	private const MINIMUM_KEY_LENGTH = 2048;

	final public function sign(string $payload, Key $key): string
	{
		try {
			$private = Phpseclib::loadPrivateKey($key->contents(), $key->passphrase());
		} catch (\InvalidArgumentException $e) {
			throw new InvalidKeyProvided($e->getMessage(), 0, $e);
		}

		if (!Phpseclib::isRsaPrivateKey($private)) {
			throw InvalidKeyProvided::incompatibleKeyType('RSA', get_class($private));
		}

		$this->assertKeyLength($private);

		try {
			return Phpseclib::pssSign($private, $this->algorithm(), $payload);
		} catch (\InvalidArgumentException $e) {
			throw new InvalidKeyProvided($e->getMessage(), 0, $e);
		}
	}

	final public function verify(string $expected, string $payload, Key $key): bool
	{
		try {
			$public = Phpseclib::loadPublicKey($key->contents());
		} catch (\InvalidArgumentException $e) {
			throw new InvalidKeyProvided($e->getMessage(), 0, $e);
		}

		if (!Phpseclib::isRsaPublicKey($public)) {
			throw InvalidKeyProvided::incompatibleKeyType('RSA', get_class($public));
		}

		$this->assertKeyLength($public);

		try {
			return Phpseclib::pssVerify($public, $this->algorithm(), $payload, $expected);
		} catch (\InvalidArgumentException $e) {
			throw new InvalidKeyProvided($e->getMessage(), 0, $e);
		}
	}

	/**
	 * Returns which algorithm to be used to create/verify the signature (using phpseclib hash identifiers)
	 *
	 * @internal
	 */
	abstract public function algorithm(): string;

	private function assertKeyLength(object $key): void
	{
		$length = Phpseclib::keyLength($key);
		if ($length < self::MINIMUM_KEY_LENGTH) {
			throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH, $length);
		}
	}
}
