<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\Support\RemoteListCache;

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
        protected RemoteListCache $remoteListCache,
    ) {}

    public function register(Application $app, array $options): void
    {
        $this->sourceUrl = $options['source'] ?? AbuseIpSource::Days60->url();
        $this->blacklistIps = $options['blacklist'] ?? [];
        $this->whitelistIps = $options['whitelist'] ?? ['127.0.0.1'];
    }

    public function updateSource(): void
    {
        $this->remoteListCache->update(
            static::LIST_CACHE_KEY,
            $this->sourceUrl,
            'ips',
            $this->parseAbuseIpDatabase(...),
        );

        $this->abuseIpList = null;
        $this->lastUpdatedAt = CarbonImmutable::now();
    }

    protected function getAbuseIpList(): array
    {
        if ($this->abuseIpList === null) {
            $this->abuseIpList = $this->remoteListCache->get(
                static::LIST_CACHE_KEY,
                $this->sourceUrl,
                'ips',
                static::class,
                $this->parseAbuseIpDatabase(...),
            );

            $cacheData = $this->storage->get(static::LIST_CACHE_KEY);
            $this->lastUpdatedAt = is_array($cacheData) && isset($cacheData['updated_at'])
                ? CarbonImmutable::createFromTimestamp($cacheData['updated_at'])
                : null;
        }

        return $this->abuseIpList;
    }

    /**
     * @return array<int,int>
     */
    protected function parseAbuseIpDatabase(string $body): array
    {
        return Collection::make(explode(PHP_EOL, $body))
            ->map(fn (string $line) => explode(' ', ltrim($line), limit: 2)[0])
            ->filter(fn (string $line) => filter_var($line, FILTER_VALIDATE_IP) !== false)
            ->map(fn (string $ip) => ip2long($ip))
            ->filter(fn (false|int $longIp) => $longIp !== false)
            ->values()
            ->all();
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
