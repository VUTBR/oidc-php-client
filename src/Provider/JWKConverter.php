<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Provider;

use InvalidArgumentException;
use Vut2\Component\OpenIDConnectClient\Crypto\Phpseclib;

class JWKConverter
{
	/**
	 * Converts multiple JSON Web Keys (JWKs) to PEM format.
	 *
	 * Keys that cannot be converted are skipped with an E_USER_WARNING.
	 *
	 * @param array<mixed> $jwkSet The array of JWKs to convert.
	 *
	 * @return array<string> PEM keys, indexed by `kid` when the JWK has one.
	 *
	 * @throws InvalidArgumentException If the input $jwkSet contains non-array elements.
	 */
	public function multipleToPEM(array $jwkSet): array
	{
		$keys = [];

		foreach ($jwkSet as $jwk) {
			if (!is_array($jwk)) {
				throw new InvalidArgumentException('`multipleToPEM` can only take in an array of JWKs.');
			}

			try {
				$pem = $this->toPEM($jwk);
			} catch (InvalidArgumentException $e) {
				trigger_error($e->getMessage(), E_USER_WARNING);
				continue;
			}

			$kid = $jwk['kid'] ?? null;
			if (is_string($kid) && $kid !== '') {
				$keys[$kid] = $pem;
			} else {
				$keys[] = $pem;
			}
		}

		return $keys;
	}

	/**
	 * Converts a public JSON Web Key (JWK) to PEM format.
	 *
	 * @param array<mixed> $jwk The JWK to convert.
	 *
	 * @return string The PEM representation of the JWK.
	 * @throws InvalidArgumentException If the key type is missing, the key is private or cannot be parsed.
	 */
	public function toPEM(array $jwk): string
	{
		if (!array_key_exists('kty', $jwk)) {
			throw new InvalidArgumentException('Missing key type.');
		}

		if (array_key_exists('d', $jwk)) {
			throw new InvalidArgumentException('Only public keys are supported.');
		}

		$json = json_encode($jwk);
		if ($json === false) {
			throw new InvalidArgumentException('Unable to encode the JWK.');
		}

		return Phpseclib::toPem($json);
	}
}
