<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Crypto;

/**
 * Thin bridge over phpseclib 3 (namespace `phpseclib3`) and phpseclib 4 (namespace `phpseclib4`).
 *
 * Both major versions expose the same key API, only the root namespace differs. phpseclib 3 is the
 * only option on PHP < 8.1, phpseclib 4 is installed on newer PHP versions.
 *
 * @internal
 */
final class Phpseclib
{
	private static ?string $namespace = null;

	/**
	 * Loads a public key (PEM, JWK JSON, ...) and returns the phpseclib key object.
	 *
	 * @throws \InvalidArgumentException when the key cannot be parsed
	 */
	public static function loadPublicKey(string $key): object
	{
		/** @var class-string $loader */
		$loader = self::className('Crypt\PublicKeyLoader');

		try {
			/** @var object $public */
			$public = $loader::loadPublicKey($key);
		} catch (\Exception $e) {
			throw new \InvalidArgumentException('It was not possible to parse the public key: ' . $e->getMessage(), 0, $e);
		}

		return $public;
	}

	/**
	 * Loads a private key and returns the phpseclib key object.
	 *
	 * @throws \InvalidArgumentException when the key cannot be parsed
	 */
	public static function loadPrivateKey(string $key, string $passphrase = ''): object
	{
		/** @var class-string $loader */
		$loader = self::className('Crypt\PublicKeyLoader');

		try {
			/** @var object $private */
			$private = $passphrase === ''
				? $loader::loadPrivateKey($key)
				: $loader::loadPrivateKey($key, $passphrase);
		} catch (\Exception $e) {
			throw new \InvalidArgumentException('It was not possible to parse the private key: ' . $e->getMessage(), 0, $e);
		}

		return $private;
	}

	/**
	 * Converts any public key phpseclib understands (including a JWK) to a PKCS#8 PEM string.
	 *
	 * @throws \InvalidArgumentException when the key cannot be parsed
	 */
	public static function toPem(string $key): string
	{
		$public = self::loadPublicKey($key);
		if (!method_exists($public, 'toString')) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}

		$pem = $public->toString('PKCS8');
		if (!is_string($pem) || $pem === '') {
			throw new \InvalidArgumentException('Unable to export the key to PEM.');
		}

		return $pem;
	}

	/**
	 * Signs the payload with RSASSA-PSS using the given hash for both the digest and MGF1.
	 *
	 * @return non-empty-string
	 */
	public static function pssSign(object $privateKey, string $hash, string $payload): string
	{
		$key = self::withPss($privateKey, $hash);
		if (!method_exists($key, 'sign')) {
			throw new \InvalidArgumentException('A private key is required to sign.');
		}

		$signature = $key->sign($payload);
		if (!is_string($signature) || $signature === '') {
			throw new \InvalidArgumentException('Unable to create the signature.');
		}

		return $signature;
	}

	/**
	 * Verifies an RSASSA-PSS signature using the given hash for both the digest and MGF1.
	 */
	public static function pssVerify(object $publicKey, string $hash, string $payload, string $signature): bool
	{
		$key = self::withPss($publicKey, $hash);
		if (!method_exists($key, 'verify')) {
			throw new \InvalidArgumentException('A public key is required to verify.');
		}

		return $key->verify($payload, $signature) === true;
	}

	/**
	 * Key length in bits.
	 */
	public static function keyLength(object $key): int
	{
		if (!method_exists($key, 'getLength')) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}

		$length = $key->getLength();

		return is_int($length) ? $length : 0;
	}

	public static function isRsaPublicKey(object $key): bool
	{
		return is_a($key, self::className('Crypt\RSA\PublicKey'));
	}

	public static function isRsaPrivateKey(object $key): bool
	{
		return is_a($key, self::className('Crypt\RSA\PrivateKey'));
	}

	/**
	 * Value of `RSA::SIGNATURE_PSS` of the installed phpseclib.
	 */
	public static function signaturePss(): int
	{
		$value = constant(self::className('Crypt\RSA') . '::SIGNATURE_PSS');
		assert(is_int($value));

		return $value;
	}

	/**
	 * @return object key configured for PSS, providing sign() (private key) or verify() (public key)
	 */
	private static function withPss(object $key, string $hash): object
	{
		if (!method_exists($key, 'withPadding')) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}
		$key = $key->withPadding(self::signaturePss());

		if (!is_object($key) || !method_exists($key, 'withHash')) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}
		$key = $key->withHash($hash);

		if (!is_object($key) || !method_exists($key, 'withMGFHash')) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}
		$key = $key->withMGFHash($hash);

		if (!is_object($key)) {
			throw new \InvalidArgumentException('Unsupported key type.');
		}

		return $key;
	}

	private static function className(string $relative): string
	{
		if (self::$namespace === null) {
			if (class_exists('phpseclib4\Crypt\PublicKeyLoader')) {
				self::$namespace = 'phpseclib4';
			} elseif (class_exists('phpseclib3\Crypt\PublicKeyLoader')) {
				self::$namespace = 'phpseclib3';
			} else {
				throw new \LogicException('phpseclib/phpseclib ^3.0 or ^4.0 is required.');
			}
		}

		return self::$namespace . '\\' . $relative;
	}
}
