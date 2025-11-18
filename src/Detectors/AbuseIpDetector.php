<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;

class AbuseIpDetector implements Detector
{
    protected string $sourceUrl;

    /**
     * @var string[]
     */
    protected array $blacklistIps;

    /**
     * @var string[]
     */
    protected array $whitelistIps;

    public function register(Application $app, array $options): void
    {
        $this->sourceUrl = $options['source'] ?? AbuseIpSource::Days30->url();
        $this->blacklistIps = $options['blacklist'] ?? [];
        $this->whitelistIps = $options['whitelist'] ?? ['127.0.0.1'];
    }
}
