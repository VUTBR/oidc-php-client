<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\OptionProvider;

use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use Vut2\Component\OpenIDConnectClient\Tool\QueryString;

/**
 * `client_secret_basic`: client credentials are sent in the `Authorization: Basic` header.
 */
class ClientSecretBasicOptionProvider extends HttpBasicAuthOptionProvider
{
	/**
	 * @param array<mixed> $params
	 */
	protected function getAccessTokenBody(array $params)
	{
		return QueryString::build($params);
	}
}
