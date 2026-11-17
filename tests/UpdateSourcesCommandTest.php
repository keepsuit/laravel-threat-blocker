<?php

use Illuminate\Support\Facades\Http;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;

use function Pest\Laravel\artisan;

test('a failing source does not stop the update of the others', function () {
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => ['source' => 'https://example.test/ips.txt'],
        EmailReputationDetector::class => ['source' => 'https://example.test/domains.txt'],
    ]);

    Http::fake([
        'https://example.test/ips.txt' => Http::response('', 500),
        'https://example.test/domains.txt' => Http::response("blocked.example\n"),
    ]);

    artisan('threat-blocker:update')->assertFailed();

    expect(app(StorageDriver::class)->get(AbuseIpDetector::LIST_CACHE_KEY))->toBeNull()
        ->and(app(StorageDriver::class)->get(EmailReputationDetector::LIST_CACHE_KEY))->items->toBe(['blocked.example' => true]);
});
