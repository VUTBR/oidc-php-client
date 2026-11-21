<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test\Support;

/**
 * RSA key pairs generated once per test run.
 */
final class TestKeys
{
	/** @var array<string, array{private: string, public: string, jwk: array<string, string>}> */
	private static array $keys = [];

	/**
	 * @return array{private: string, public: string, jwk: array<string, string>}
	 */
	public static function rsa(string $name = 'default'): array
	{
		if (!isset(self::$keys[$name])) {
			$resource = openssl_pkey_new([
				'private_key_bits' => 2048,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			]);
			if ($resource === false) {
				throw new \RuntimeException('Unable to generate an RSA key: ' . openssl_error_string());
			}

			$private = '';
			openssl_pkey_export($resource, $private);
			$details = openssl_pkey_get_details($resource);
			if (!is_array($details)) {
				throw new \RuntimeException('Unable to read the RSA key details.');
			}

			self::$keys[$name] = [
				'private' => $private,
				'public' => $details['key'],
				'jwk' => [
					'kty' => 'RSA',
					'use' => 'sig',
					'alg' => 'RS256',
					'kid' => $name,
					'n' => self::base64Url($details['rsa']['n']),
					'e' => self::base64Url($details['rsa']['e']),
				],
			];
		}

		return self::$keys[$name];
	}

	public static function base64Url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
