<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Test\Support;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Minimal PSR-18 client returning queued responses and recording requests.
 * Like real PSR-18 clients, it does not throw on 4xx/5xx responses.
 */
final class ArrayPsr18Client implements ClientInterface
{
	/** @var array<ResponseInterface> */
	private array $responses;

	/** @var array<RequestInterface> */
	public array $requests = [];

	/**
	 * @param array<ResponseInterface> $responses
	 */
	public function __construct(array $responses = [])
	{
		$this->responses = $responses;
	}

	public function append(ResponseInterface $response): void
	{
		$this->responses[] = $response;
	}

	public function sendRequest(RequestInterface $request): ResponseInterface
	{
		$this->requests[] = $request;

		$response = array_shift($this->responses);
		if ($response === null) {
			throw new \RuntimeException('No queued response for ' . $request->getMethod() . ' ' . $request->getUri());
		}

		return $response;
	}
}
