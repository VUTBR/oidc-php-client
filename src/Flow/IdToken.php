<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Flow;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;

/**
 * Access token response that also carries an ID token.
 *
 * The constructor only parses the ID token; signature and claims are validated by the provider.
 */
final class IdToken extends AccessToken
{
	private ?Token\Plain $idToken = null;

	/**
	 * @param array<string, mixed> $options Token endpoint response
	 * @throws InvalidTokenException when the id_token cannot be parsed
	 */
	public function __construct(array $options = [])
	{
		parent::__construct($options);

		if (isset($this->values['id_token'])) {
			$idToken = $this->values['id_token'];
			unset($this->values['id_token']);

			if (!is_string($idToken) || $idToken === '') {
				throw new InvalidTokenException('The id_token must be a non-empty string.');
			}

			try {
				$token = (new Parser(new JoseEncoder()))->parse($idToken);
			} catch (JwtException $e) {
				throw new InvalidTokenException('Unable to parse the id_token: ' . $e->getMessage(), 0, $e);
			}

			if (!$token instanceof Token\Plain) {
				throw new InvalidTokenException('The id_token must be a signed (JWS) token.');
			}

			$this->idToken = $token;
		}
	}

	public function getIdToken(): ?Token\Plain
	{
		return $this->idToken;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$parameters = parent::jsonSerialize();

		if ($this->idToken !== null) {
			$parameters['id_token'] = $this->idToken->toString();
		}

		return $parameters;
	}
}
