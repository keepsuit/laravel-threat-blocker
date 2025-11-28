<?php

use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\ThreatBlocker;
use Spatie\TestTime\TestTime;

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

    expect(invade($detector))
        ->sourceUrl->toBe(\Keepsuit\ThreatBlocker\Enums\AbuseIpSource::Days60->url())
        ->blacklistIps->toBe([])
        ->whitelistIps->toBe(['127.0.0.1']);
});

test('update abuseip detector source', function () {
    TestTime::freezeAtSecond();

    Http::fake([
        'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/*' => function () {
            return Http::response(file_get_contents(__DIR__.'/../stubs/abuseipdb-s100-1d.ipv4'));
        },
    ]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    $detector->updateSource();

    $cacheData = app(StorageDriver::class)->get('abuseip-list');

    expect($cacheData)->toBeArray()
        ->{'updated_at'}->toBe(now()->timestamp)
        ->{'ips'}->toHaveCount(52204);
});

test('load cached data with old format', function () {
    app(StorageDriver::class)->set('abuseip-list', [350046382, 350046449, 350103321]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect(invade($detector))
        ->getAbuseIpList()->toBe([350046382, 350046449, 350103321])
        ->lastUpdatedAt->toBeNull();
});

test('load cached data with new format', function () {
    $timestamp = now()->subDay()->timestamp;

    app(StorageDriver::class)->set('abuseip-list', [
        'ips' => [350046382, 350046449, 350103321],
        'updated_at' => $timestamp,
    ]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect(invade($detector))
        ->getAbuseIpList()->toBe([350046382, 350046449, 350103321])
        ->lastUpdatedAt->not->toBeNull()
        ->lastUpdatedAt->timestamp->toBe($timestamp);
});
