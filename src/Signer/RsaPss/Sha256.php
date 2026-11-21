<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Signer\RsaPss;

use Vut2\Component\OpenIDConnectClient\Signer\RsaPss;

final class Sha256 extends RsaPss
{
	public function algorithmId(): string
	{
		return 'PS256';
	}

	public function algorithm(): string
	{
		return 'sha256';
	}
}
