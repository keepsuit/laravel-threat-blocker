<?php

namespace Keepsuit\ThreatBlocker\Commands;

use GuzzleHttp\Psr7\Utils;
use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\LazyCollection;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\ThreatBlocker;

class UpdateAbuseIpCommand extends Command
{
    public $signature = 'threat-blocker:update-abuseip';

    public $description = 'Update AbuseIp database';

    public function handle(ThreatBlocker $threatBlocker, StorageDriver $storage): int
    {
        $this->outputComponents()->info('Fetching AbuseIp database...');

        $detector = $threatBlocker->getDetector(AbuseIpDetector::class);

        if ($detector === null) {
            $this->outputComponents()->error('AbuseIpDetector is not registered.');

            return self::FAILURE;
        }

        $ips = $this->fetchAbuseIpDatabase($detector->sourceUrl);

        $storage->set('abuseip-list', $ips->all());

        return self::SUCCESS;
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
