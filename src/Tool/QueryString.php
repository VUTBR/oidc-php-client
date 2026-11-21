<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Tool;

/**
 * Builds an application/x-www-form-urlencoded string where list values are sent as repeated
 * parameters (`resource=a&resource=b`, as required by RFC 8707) instead of PHP's `resource[0]=a`.
 *
 * @internal
 */
final class QueryString
{
	/**
	 * @param array<mixed> $params
	 */
	public static function build(array $params): string
	{
		$parts = [];

		foreach ($params as $key => $value) {
			if ($value === null) {
				continue;
			}

			$values = is_array($value) && self::isList($value) ? $value : [$value];
			foreach ($values as $item) {
				if ($item === null) {
					continue;
				}

				$part = http_build_query([$key => $item], '', '&', PHP_QUERY_RFC3986);
				if ($part !== '') {
					$parts[] = $part;
				}
			}
		}

		return implode('&', $parts);
	}

	/**
	 * @param array<mixed> $value
	 */
	private static function isList(array $value): bool
	{
		return $value === [] || array_keys($value) === range(0, count($value) - 1);
	}
}
