<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use GuzzleHttp\Psr7\Utils;
use Illuminate\Foundation\Application;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\LazyCollection;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;

class AbuseIpDetector implements Detector, SourceUpdatable
{
    protected const LIST_CACHE_KEY = 'abuseip-list';

    public protected(set) string $sourceUrl;

    /**
     * @var string[]
     */
    public protected(set) array $blacklistIps;

    /**
     * @var string[]
     */
    public protected(set) array $whitelistIps;

    public function __construct(
        protected StorageDriver $storage,
    ) {}

    public function register(Application $app, array $options): void
    {
        $this->sourceUrl = $options['source'] ?? AbuseIpSource::Days30->url();
        $this->blacklistIps = $options['blacklist'] ?? [];
        $this->whitelistIps = $options['whitelist'] ?? ['127.0.0.1'];
    }

    public function updateSource(): void
    {
        $ips = $this->fetchAbuseIpDatabase($this->sourceUrl);

        $this->storage->set(static::LIST_CACHE_KEY, $ips->all());
    }

    /**
     * @return Collection<array-key,int>
     *
     * @throws ConnectionException
     */
    protected function fetchAbuseIpDatabase(string $sourceUrl): Collection
    {
        $response = Http::throw()->get($sourceUrl);

        $lines = new LazyCollection(function () use ($response) {
            $body = $response->getBody();

            while (! $body->eof()) {
                yield Utils::readLine($body);
            }
        });

        return $lines
            ->map(fn (string $line) => preg_replace('/\s*#.*$/', '', trim($line)) ?: '')
            ->filter(fn (string $line) => filter_var($line, FILTER_VALIDATE_IP) !== false)
            ->map(fn (string $ip) => ip2long($ip))
            ->values()
            ->collect();
    }
}
