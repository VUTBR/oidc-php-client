<?php
declare(strict_types=1);

/**
 * Shared configuration of the examples.
 *
 * Environment variables:
 *   OIDC_CLIENT_ID, OIDC_CLIENT_SECRET   client registered at id.vut.cz
 *   OIDC_REDIRECT_URI                    default http://localhost:8002/client.php
 *   OIDC_ISSUER                          default https://id.vut.cz/auth
 */

use Vut2\Component\OpenIDConnectClient\Examples\SessionRegistry;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

require __DIR__ . '/../vendor/autoload.php';

function createProvider(): VutOpenIDConnectProvider
{
	return new VutOpenIDConnectProvider(
		[
			'clientId' => (string)getenv('OIDC_CLIENT_ID'),
			'clientSecret' => (string)getenv('OIDC_CLIENT_SECRET'),
			'redirectUri' => getenv('OIDC_REDIRECT_URI') ?: 'http://localhost:8002/client.php',
			'issuer' => getenv('OIDC_ISSUER') ?: VutOpenIDConnectProvider::DEFAULT_ISSUER,
			'scopes' => ['openid', 'profile', 'email', 'offline_access'],
		],
		[
			// Any PSR-18 client works as well, e.g.
			// 'httpClient' => new \Symfony\Component\HttpClient\Psr18Client(
			//     \Symfony\Component\HttpClient\HttpClient::create(),
			//     new \GuzzleHttp\Psr7\HttpFactory(),
			//     new \GuzzleHttp\Psr7\HttpFactory()
			// ),
			// Cache discovery and JWKS (PSR-6), e.g. new \Symfony\Component\Cache\Adapter\FilesystemAdapter()
			// 'cache' => $cache,
		]
	);
}

function sessionRegistry(): SessionRegistry
{
	return new SessionRegistry(sys_get_temp_dir() . '/oidc-client-example-sessions.json');
}

function e(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
