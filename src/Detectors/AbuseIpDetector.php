<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Foundation\Application;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
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

    protected ?CarbonInterface $lastUpdatedAt = null;

    public function __construct(
        protected StorageDriver $storage,
    ) {}

    public function register(Application $app, array $options): void
    {
        $this->sourceUrl = $options['source'] ?? AbuseIpSource::Days60->url();
        $this->blacklistIps = $options['blacklist'] ?? [];
        $this->whitelistIps = $options['whitelist'] ?? ['127.0.0.1'];
    }

    public function updateSource(): void
    {
        $lastUpdatedAt = CarbonImmutable::now();
        $ips = $this->fetchAbuseIpDatabase($this->sourceUrl)->all();

        $this->storage->set(static::LIST_CACHE_KEY, [
            'ips' => $ips,
            'updated_at' => $lastUpdatedAt->timestamp,
        ]);

        $this->abuseIpList = $ips;
        $this->lastUpdatedAt = $lastUpdatedAt;
    }

    /**
     * @return Collection<array-key,int>
     *
     * @throws ConnectionException
     */
    protected function fetchAbuseIpDatabase(string $sourceUrl): Collection
    {
        $response = Http::throw()->get($sourceUrl);

        $lines = Collection::make(explode(PHP_EOL, $response->body()));

        return $lines
            ->map(fn (string $line) => explode(' ', ltrim($line), limit: 2)[0])
            ->filter(fn (string $line) => filter_var($line, FILTER_VALIDATE_IP) !== false)
            ->map(fn (string $ip) => ip2long($ip))
            ->filter(fn (false|int $longIp) => $longIp !== false)
            ->values();
    }

    protected function getAbuseIpList(): array
    {
        if ($this->abuseIpList === null) {
            $cacheData = $this->storage->get(static::LIST_CACHE_KEY);

            if (isset($cacheData['updated_at'])) {
                $this->lastUpdatedAt = Carbon::createFromTimestamp($cacheData['updated_at']);
                $this->abuseIpList = $cacheData['ips'];
            } else {
                $this->lastUpdatedAt = null;
                $this->abuseIpList = $cacheData;
            }
        }

        if ($this->abuseIpList === null) {
            Log::warning('AbuseIpDetector: AbuseIP database not found in storage, fetching from source...');
            rescue(fn () => $this->updateSource());
        }

        if ($this->lastUpdatedAt === null || $this->lastUpdatedAt->isBefore(Carbon::now()->subDays(3))) {
            \Illuminate\Support\defer(fn () => $this->updateSource());
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
