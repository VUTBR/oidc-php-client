<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test\Support;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;

/**
 * Builds signed JWTs for tests; works with lcobucci/jwt 4 (mutable builder) and 5 (immutable builder).
 */
final class TokenFactory
{
	public const ISSUER = 'https://id.vut.cz/auth';
	public const CLIENT_ID = 'a57574b2-b7b2-4962-ad77-b908874691cc';
	public const CLIENT_SECRET = 'test-client-secret-that-is-long-enough-for-hs512-algorithms-0123456789';
	public const REDIRECT_URI = 'https://app.example/callback';
	public const NONCE = 'nonce-0123456789';
	public const PKCE = 'pkce-verifier-0123456789-0123456789-0123456789-0123456789-0123';
	/** 2026-01-01T00:00:00Z */
	public const NOW = 1767225600;

	/**
	 * Default ID token claims; a null value removes the claim.
	 *
	 * @param array<string, mixed> $claims
	 * @param array<string, mixed> $headers
	 */
	public static function idToken(array $claims = [], array $headers = [], ?Signer $signer = null, ?string $key = null): string
	{
		$claims += [
			'iss' => self::ISSUER,
			'aud' => self::CLIENT_ID,
			'sub' => 'user-1',
			'iat' => self::NOW,
			'exp' => self::NOW + 600,
			'nonce' => self::NONCE,
			'auth_time' => self::NOW - 60,
			'name' => 'Jana Nováková',
			'email' => 'jana@example.com',
		];
		$headers += ['kid' => 'default'];

		return self::build($claims, $headers, $signer, $key);
	}

	/**
	 * Default back-channel logout token claims; a null value removes the claim.
	 *
	 * @param array<string, mixed> $claims
	 */
	public static function logoutToken(array $claims = []): string
	{
		$claims += [
			'iss' => self::ISSUER,
			'aud' => self::CLIENT_ID,
			'sub' => 'user-1',
			'sid' => 'session-1',
			'iat' => self::NOW,
			'exp' => self::NOW + 120,
			'jti' => 'logout-1',
			'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
		];

		return self::build($claims, ['kid' => 'default', 'typ' => 'logout+jwt'], null, null);
	}

	/**
	 * Unsigned token with `alg: none`.
	 *
	 * @param array<string, mixed> $claims
	 */
	public static function unsigned(array $claims): string
	{
		$header = TestKeys::base64Url((string)json_encode(['alg' => 'none', 'typ' => 'JWT']));
		$payload = TestKeys::base64Url((string)json_encode($claims));

		return $header . '.' . $payload . '.';
	}

	/**
	 * @param array<string, mixed> $claims
	 * @param array<string, mixed> $headers
	 */
	private static function build(array $claims, array $headers, ?Signer $signer, ?string $key): string
	{
		$builder = new Builder(new JoseEncoder(), ChainedFormatter::default());

		foreach ($headers as $name => $value) {
			if ($value !== null) {
				$builder = $builder->withHeader($name, $value);
			}
		}

		foreach ($claims as $name => $value) {
			if ($value === null) {
				continue;
			}

			switch ($name) {
				case 'iss':
					$builder = $builder->issuedBy($value);
					break;
				case 'aud':
					foreach ((array)$value as $audience) {
						$builder = $builder->permittedFor($audience);
					}
					break;
				case 'sub':
					$builder = $builder->relatedTo($value);
					break;
				case 'jti':
					$builder = $builder->identifiedBy($value);
					break;
				case 'iat':
					$builder = $builder->issuedAt(new \DateTimeImmutable('@' . $value));
					break;
				case 'exp':
					$builder = $builder->expiresAt(new \DateTimeImmutable('@' . $value));
					break;
				case 'nbf':
					$builder = $builder->canOnlyBeUsedAfter(new \DateTimeImmutable('@' . $value));
					break;
				default:
					$builder = $builder->withClaim($name, $value);
			}
		}

		$signer = $signer ?? new Signer\Rsa\Sha256();
		$key = $key ?? TestKeys::rsa()['private'];

		return $builder->getToken($signer, InMemory::plainText($key))->toString();
	}
}
