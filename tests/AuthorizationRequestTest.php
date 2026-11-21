<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use Vut2\Component\OpenIDConnectClient\Exception\AuthorizationErrorException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidAuthorizationResponseException;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

class AuthorizationRequestTest extends ProviderTestCase
{
	public function testAuthorizationUrl(): void
	{
		$provider = $this->createProvider();
		$url = $provider->getAuthorizationUrl();
		$query = self::query($url);

		self::assertStringStartsWith('https://id.vut.cz/auth/common/oauth2/authorize?', $url);
		self::assertSame('code', $query['response_type']);
		self::assertSame(TokenFactory::CLIENT_ID, $query['client_id']);
		self::assertSame(TokenFactory::REDIRECT_URI, $query['redirect_uri']);
		self::assertSame('openid profile email', $query['scope']);
		self::assertSame('S256', $query['code_challenge_method']);
		self::assertSame($provider->getState(), $query['state']);
		self::assertSame($provider->getNonce(), $query['nonce']);
		self::assertArrayNotHasKey('approval_prompt', $query);

		$expectedChallenge = rtrim(strtr(base64_encode(hash('sha256', (string)$provider->getPkceCode(), true)), '+/', '-_'), '=');
		self::assertSame($expectedChallenge, $query['code_challenge']);
		self::assertNotEmpty($provider->getNonce());
	}

	public function testOpenidScopeIsAlwaysAdded(): void
	{
		$provider = $this->createProvider(['scopes' => ['email']]);

		self::assertContains('openid', explode(' ', (string)self::query($provider->getAuthorizationUrl())['scope']));
	}

	public function testOptionalParameters(): void
	{
		$provider = $this->createProvider();
		$url = $provider->getAuthorizationUrl([
			'acr_values' => ['urn:mfa', 'urn:mfa:passwordless'],
			'max_age' => 300,
			'prompt' => 'login',
			'resource' => ['https://api.example/', 'https://other.example/'],
		]);
		$query = self::query($url);

		self::assertSame('urn:mfa urn:mfa:passwordless', $query['acr_values']);
		self::assertSame('300', $query['max_age']);
		self::assertSame(['acrValues' => 'urn:mfa urn:mfa:passwordless', 'maxAge' => 300], $provider->getAuthorizationRequirements());
		self::assertSame('login', $query['prompt']);
		// RFC 8707: repeated parameter, not resource[0]
		self::assertStringContainsString('resource=https%3A%2F%2Fapi.example%2F&resource=https%3A%2F%2Fother.example%2F', $url);
	}

	public function testAuthorizationRequirementsAreResetForEachRequest(): void
	{
		$provider = $this->createProvider();
		$provider->getAuthorizationUrl(['acr_values' => 'urn:mfa', 'max_age' => 0]);
		self::assertSame(['acrValues' => 'urn:mfa', 'maxAge' => 0], $provider->getAuthorizationRequirements());

		$provider->getAuthorizationUrl();
		self::assertSame([], $provider->getAuthorizationRequirements());
	}

	public function testValidResponseReturnsCode(): void
	{
		$provider = $this->createProvider();

		self::assertSame('the-code', $provider->validateAuthorizationResponse(
			['code' => 'the-code', 'state' => 'state-1', 'iss' => TokenFactory::ISSUER],
			'state-1'
		));
	}

	public function testIssIsOptionalWhenNotAdvertised(): void
	{
		$provider = $this->createProvider();

		self::assertSame('the-code', $provider->validateAuthorizationResponse(['code' => 'the-code', 'state' => 'state-1'], 'state-1'));
	}

	public function testIssIsRequiredWhenAdvertised(): void
	{
		$provider = $this->createProvider([], self::discovery([], true));

		$this->expectException(InvalidAuthorizationResponseException::class);
		$this->expectExceptionMessage('missing the "iss"');

		$provider->validateAuthorizationResponse(['code' => 'the-code', 'state' => 'state-1'], 'state-1');
	}

	public function testWrongIssIsRejected(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidAuthorizationResponseException::class);

		$provider->validateAuthorizationResponse(
			['code' => 'the-code', 'state' => 'state-1', 'iss' => 'https://attacker.example'],
			'state-1'
		);
	}

	public function testWrongStateIsRejected(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidAuthorizationResponseException::class);
		$this->expectExceptionMessage('Invalid state');

		$provider->validateAuthorizationResponse(['code' => 'the-code', 'state' => 'other'], 'state-1');
	}

	public function testEmptyExpectedStateIsRejected(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidAuthorizationResponseException::class);

		$provider->validateAuthorizationResponse(['code' => 'the-code', 'state' => ''], '');
	}

	public function testMissingCodeIsRejected(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidAuthorizationResponseException::class);

		$provider->validateAuthorizationResponse(['state' => 'state-1'], 'state-1');
	}

	public function testErrorResponse(): void
	{
		$provider = $this->createProvider([], self::discovery([], true));

		try {
			$provider->validateAuthorizationResponse([
				'error' => 'unmet_authentication_requirements',
				'error_description' => 'Unable to meet the requested assurance level (acr value).',
				'state' => 'state-1',
				'iss' => TokenFactory::ISSUER,
			], 'state-1');
			self::fail('Expected AuthorizationErrorException');
		} catch (AuthorizationErrorException $e) {
			self::assertTrue($e->isUnmetAuthenticationRequirements());
			self::assertSame('unmet_authentication_requirements', $e->getError());
			self::assertSame('Unable to meet the requested assurance level (acr value).', $e->getErrorDescription());
		}
	}

	public function testErrorResponseWithWrongIssIsNotTrusted(): void
	{
		$provider = $this->createProvider();

		$this->expectException(InvalidAuthorizationResponseException::class);

		$provider->validateAuthorizationResponse(
			['error' => 'access_denied', 'state' => 'state-1', 'iss' => 'https://attacker.example'],
			'state-1'
		);
	}
}
