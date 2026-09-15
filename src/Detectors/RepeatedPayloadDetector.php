<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;

/**
 * Detects form submissions built from a static template: a bot filling the same
 * values on every request, rotating the identifying field (an email, a username)
 * and the source address, which defeats both honeypots and per-IP rate limits.
 *
 * Fingerprints only the configured fields on the configured paths, so it never
 * acts on a form it was not pointed at.
 */
class RepeatedPayloadDetector implements Detector
{
    public const string KEY_PREFIX = 'repeated-payload';

    /**
     * @var array<string,string[]>
     */
    protected array $paths = [];

    protected int $window = 3600;

    protected int $threshold = 10;

    public function __construct(
        protected StorageDriver $storage,
    ) {}

    public function register(Application $app, array $options): void
    {
        $this->paths = $options['paths'] ?? [];
        $this->window = (int) ($options['window'] ?? 3600);
        $this->threshold = (int) ($options['threshold'] ?? 10);
    }

    /**
     * {@inheritDoc}
     */
    public function check(Request $request): void
    {
        if (! $request->isMethod('POST')) {
            return;
        }

        $fingerprint = $this->fingerprint($request);

        if ($fingerprint === null) {
            return;
        }

        if ($this->hits($fingerprint) > $this->threshold) {
            throw new ThreatDetectedException('Repeated form payload detected.');
        }
    }

    protected function fingerprint(Request $request): ?string
    {
        $fields = null;

        foreach ($this->paths as $pattern => $patternFields) {
            if ($request->is($pattern)) {
                $fields = $patternFields;

                break;
            }
        }

        if ($fields === null) {
            return null;
        }

        $values = $request->only($fields);

        if ($values === []) {
            return null;
        }

        ksort($values);

        $payload = [$request->path(), $values];

        // A bot is free to post payloads that are not valid UTF-8, which json_encode rejects.
        $encoded = json_encode($payload) ?: serialize($payload);

        return hash('xxh128', $encoded);
    }

    /**
     * Counts the submissions sharing a fingerprint, in fixed windows of `window` seconds.
     */
    protected function hits(string $fingerprint): int
    {
        $key = static::KEY_PREFIX.'.'.$fingerprint;
        $now = Carbon::now()->getTimestamp();

        $stored = $this->storage->get($key);
        $expired = ! is_array($stored) || ($now - ($stored['started_at'] ?? 0)) >= $this->window;

        $hits = $expired ? 1 : ($stored['hits'] ?? 0) + 1;
        $startedAt = $expired ? $now : $stored['started_at'];

        // ponytail: read-modify-write, so bursts can undercount. An atomic counter on the
        // storage driver is the upgrade if a bot ever squeezes through the gap.
        $this->storage->set($key, [
            'hits' => $hits,
            'started_at' => $startedAt,
        ], $this->window);

        return $hits;
    }
}
