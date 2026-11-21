<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\OptionProvider;

use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use Vut2\Component\OpenIDConnectClient\Tool\QueryString;

/**
 * `client_secret_post`: client credentials are sent in the request body.
 */
class ClientSecretPostOptionProvider extends PostAuthOptionProvider
{
	/**
	 * @param array<mixed> $params
	 */
	protected function getAccessTokenBody(array $params)
	{
		return QueryString::build($params);
	}
}
