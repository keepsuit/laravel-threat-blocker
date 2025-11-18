<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use GuzzleHttp\Psr7\Utils;
use Illuminate\Foundation\Application;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\LazyCollection;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;

class AbuseIpDetector implements Detector, SourceUpdatable
{
    public const string LIST_CACHE_KEY = 'abuseip-list';

    protected string $sourceUrl;

    /**
     * @var string[]
     */
    protected array $blacklistIps;

    /**
     * @var string[]
     */
    protected array $whitelistIps;

    /**
     * @var int[]|null
     */
    protected ?array $abuseIpList = null;

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
        $ips = $this->fetchAbuseIpDatabase($this->sourceUrl)->all();

        $this->storage->set(static::LIST_CACHE_KEY, $ips);

        $this->abuseIpList = $ips;
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

    protected function getAbuseIpList(): array
    {
        if ($this->abuseIpList === null) {
            $this->abuseIpList = $this->storage->get(static::LIST_CACHE_KEY);
        }

        if ($this->abuseIpList === null) {
            try {
                $this->updateSource();
            } catch (\Throwable $throwable) {
                if (app()->runningUnitTests()) {
                    throw $throwable;
                }
            }
        }

        return $this->abuseIpList ?? [];
    }

    /**
     * {@inheritDoc}
     */
    public function check(Request $request): void
    {
        $ip = $request->ip();

        if ($ip === null) {
            return;
        }

        if (in_array($ip, $this->whitelistIps, true)) {
            return;
        }

        if (in_array($ip, $this->blacklistIps, true)) {
            throw new ThreatDetectedException('Blacklisted IP detected.');
        }

        $longIp = ip2long($ip);
        if ($longIp === false) {
            return;
        }

        if (in_array($longIp, $this->getAbuseIpList(), true)) {
            throw new ThreatDetectedException('AbuseIP database match detected.');
        }
    }
}
