<?php

use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\ThreatBlocker;

beforeEach(function () {
    config()->set('threat-blocker.detectors', [
        Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::class => true,
    ]);
});

test('register abuseip detector with default settings', function () {
    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect($detector)
        ->not->toBeNull()
        ->toBeInstanceOf(AbuseIpDetector::class);

    expect($detector)
        ->sourceUrl->toBe(\Keepsuit\ThreatBlocker\Enums\AbuseIpSource::Days30->url())
        ->blacklistIps->toBe([])
        ->whitelistIps->toBe(['127.0.0.1']);
});

test('update abuseip detector source', function () {
    Http::fake([
        'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/*' => function () {
            return Http::response(file_get_contents(__DIR__.'/../stubs/abuseipdb-s100-1d.ipv4'));
        },
    ]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    $detector->updateSource();

    expect(app(StorageDriver::class)->get('abuseip-list'))
        ->toBeArray()
        ->toHaveCount(52204);
});
