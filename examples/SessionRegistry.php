<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Examples;

/**
 * Example mapping of OpenID Provider sessions (`sid`) and users (`sub`) to local PHP session IDs.
 *
 * Back-channel logout requests are sent by the OpenID Provider server, not by the user's browser,
 * so the application has to find the local session itself. In production use a database or Redis.
 */
final class SessionRegistry
{
	private string $file;

	public function __construct(string $file)
	{
		$this->file = $file;
	}

	public function register(string $phpSessionId, string $sub, ?string $sid): void
	{
		$this->modify(static function (array $sessions) use ($phpSessionId, $sub, $sid): array {
			$sessions[$phpSessionId] = ['sub' => $sub, 'sid' => $sid];

			return $sessions;
		});
	}

	public function unregister(string $phpSessionId): void
	{
		$this->modify(static function (array $sessions) use ($phpSessionId): array {
			unset($sessions[$phpSessionId]);

			return $sessions;
		});
	}

	/**
	 * Removes and returns the PHP session IDs matching the logout token.
	 * With `sid` only that OP session is logged out, with `sub` only all sessions of the user.
	 *
	 * @return array<string>
	 */
	public function pullSessions(?string $sub, ?string $sid): array
	{
		$matched = [];
		$this->modify(static function (array $sessions) use ($sub, $sid, &$matched): array {
			foreach ($sessions as $phpSessionId => $session) {
				$matches = $sid !== null
					? $session['sid'] === $sid && ($sub === null || $session['sub'] === $sub)
					: $session['sub'] === $sub;
				if ($matches) {
					$matched[] = (string)$phpSessionId;
					unset($sessions[$phpSessionId]);
				}
			}

			return $sessions;
		});

		return $matched;
	}

	/**
	 * @param callable(array<string, array{sub: string, sid: ?string}>): array<string, array{sub: string, sid: ?string}> $callback
	 */
	private function modify(callable $callback): void
	{
		$handle = fopen($this->file, 'c+');
		if ($handle === false) {
			throw new \RuntimeException('Unable to open ' . $this->file);
		}

		try {
			flock($handle, LOCK_EX);
			$content = stream_get_contents($handle);
			$sessions = $content !== false && $content !== '' ? json_decode($content, true) : [];
			$sessions = $callback(is_array($sessions) ? $sessions : []);

			ftruncate($handle, 0);
			rewind($handle);
			fwrite($handle, (string)json_encode($sessions));
			fflush($handle);
		} finally {
			flock($handle, LOCK_UN);
			fclose($handle);
		}
	}
}
