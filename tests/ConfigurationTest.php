<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test;

use Vut2\Component\OpenIDConnectClient\Exception\InvalidConfigurationException;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;
use Vut2\Component\OpenIDConnectClient\Provider\VutProvider;
use Vut2\Component\OpenIDConnectClient\Test\Support\ProviderTestCase;
use Vut2\Component\OpenIDConnectClient\Test\Support\TestKeys;
use Vut2\Component\OpenIDConnectClient\Test\Support\TokenFactory;

class ConfigurationTest extends ProviderTestCase
{
	public function testDiscoveryConfiguresEndpoints(): void
	{
		$provider = $this->createProvider();

		self::assertSame('https://id.vut.cz/auth/.well-known/openid-configuration', (string)$this->history[0]['request']->getUri());
		self::assertSame('https://id.vut.cz/auth/.well-known/jwks.json', (string)$this->history[1]['request']->getUri());
		self::assertSame('https://id.vut.cz/auth/common/oauth2/authorize', $provider->getBaseAuthorizationUrl());
		self::assertSame('https://id.vut.cz/auth/common/oauth2/token', $provider->getBaseAccessTokenUrl([]));
		self::assertSame('https://id.vut.cz/auth/common/oauth2/revoke', $provider->getBaseRevokeTokenUrl([]));
		self::assertSame(TokenFactory::ISSUER, $provider->getIdTokenIssuer());
		self::assertFalse($provider->isAuthorizationResponseIssParameterSupported());
	}

	public function testDefaultIssuerIsVut(): void
	{
		$provider = $this->createProvider(['issuer' => null]);

		self::assertSame('https://id.vut.cz/auth/.well-known/openid-configuration', (string)$this->history[0]['request']->getUri());
		self::assertSame(TokenFactory::ISSUER, $provider->getIdTokenIssuer());
	}

	public function testOAuth21DiscoveryFields(): void
	{
		$provider = $this->createProvider([], self::discovery([], true));

		self::assertTrue($provider->isAuthorizationResponseIssParameterSupported());
		// both advertised, client_secret_post is preferred
		self::assertSame(VutProvider::AUTH_METHOD_CLIENT_SECRET_POST, $provider->getTokenEndpointAuthMethod());
	}

	public function testIssuerMismatchIsRejected(): void
	{
		$this->expectException(InvalidConfigurationException::class);
		$this->expectExceptionMessage('does not match the configured issuer');

		$this->createProvider([], self::discovery(['issuer' => 'https://attacker.example']));
	}

	public function testServerWithoutS256IsRejected(): void
	{
		$this->expectException(InvalidConfigurationException::class);

		$this->createProvider([], self::discovery(['code_challenge_methods_supported' => ['plain']]));
	}

	public function testPlainPkceIsRejected(): void
	{
		$this->expectException(InvalidConfigurationException::class);

		$this->createProvider(['pkceMethod' => 'plain']);
	}

	public function testClientSecretIsRequired(): void
	{
		$this->expectException(InvalidConfigurationException::class);

		$this->createProvider(['clientSecret' => '']);
	}

	public function testClientSecretBasicWhenOnlyBasicIsAdvertised(): void
	{
		$provider = $this->createProvider([], self::discovery(['token_endpoint_auth_methods_supported' => ['client_secret_basic']]));

		self::assertSame(VutProvider::AUTH_METHOD_CLIENT_SECRET_BASIC, $provider->getTokenEndpointAuthMethod());
	}

	public function testExplicitAuthMethodMustBeSupportedByServer(): void
	{
		$this->expectException(InvalidConfigurationException::class);

		$this->createProvider(
			['tokenEndpointAuthMethod' => 'client_secret_post'],
			self::discovery(['token_endpoint_auth_methods_supported' => ['client_secret_basic']])
		);
	}

	public function testManualConfigurationWithoutDiscovery(): void
	{
		$provider = new VutOpenIDConnectProvider([
			'clientId' => TokenFactory::CLIENT_ID,
			'clientSecret' => TokenFactory::CLIENT_SECRET,
			'redirectUri' => TokenFactory::REDIRECT_URI,
			'publicKey' => TestKeys::rsa()['public'],
			'idTokenIssuer' => TokenFactory::ISSUER,
		]);

		self::assertSame('https://id.vut.cz/auth/common/oauth2/authorize', $provider->getBaseAuthorizationUrl());
		self::assertSame('https://id.vut.cz/auth/oidc/userinfo', $provider->getResourceOwnerDetailsUrl(new \League\OAuth2\Client\Token\AccessToken(['access_token' => 'x'])));
	}

	public function testNoneAlgorithmCannotBeConfigured(): void
	{
		$this->expectException(InvalidConfigurationException::class);

		$this->createProvider(['idTokenSigningAlgValues' => ['none']]);
	}

	public function testUnsupportedHttpClientIsRejected(): void
	{
		$this->expectException(\InvalidArgumentException::class);

		$this->createProvider([], null, ['httpClient' => new \stdClass()]);
	}
}
