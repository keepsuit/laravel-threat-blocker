<?php

use Illuminate\Support\Defer\DeferredCallbackCollection;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
use Keepsuit\ThreatBlocker\Support\RemoteListCache;
use Keepsuit\ThreatBlocker\ThreatBlocker;
use Spatie\TestTime\TestTime;

beforeEach(function () {
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => true,
    ]);
});

test('register abuseip detector with default settings', function () {
    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect($detector)
        ->not->toBeNull()
        ->toBeInstanceOf(AbuseIpDetector::class);

    expect(invade($detector))
        ->sourceUrl->toBe(AbuseIpSource::Days60->url())
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

test('cached source expires after one year without updates', function () {
    TestTime::freezeAtSecond();

    Http::fake([
        'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/*' => Http::response("1.0.170.118\n"),
    ]);

    app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class)->updateSource();

    TestTime::addDays(364);
    expect(app(StorageDriver::class)->get('abuseip-list'))->not->toBeNull();

    TestTime::addDays(2);
    expect(app(StorageDriver::class)->get('abuseip-list'))->toBeNull();
});

test('load cached data with old format', function () {
    app(StorageDriver::class)->set('abuseip-list', [350046382, 350046449, 350103321]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect(invade($detector))
        ->getAbuseIpList()->toBe([350046382, 350046449, 350103321]);
});

test('load cached data with new format', function () {
    $timestamp = now()->subDay()->timestamp;

    app(StorageDriver::class)->set('abuseip-list', [
        'ips' => [350046382, 350046449, 350103321],
        'updated_at' => $timestamp,
    ]);

    $detector = app(ThreatBlocker::class)->getDetector(AbuseIpDetector::class);

    expect(invade($detector))
        ->getAbuseIpList()->toBe([350046382, 350046449, 350103321]);
});

test('a failed fetch of a missing source is not retried by every request', function () {
    Http::fake(['*' => Http::response('', 500)]);

    $remoteListCache = app(RemoteListCache::class);
    $fetch = fn () => $remoteListCache->get('abuseip-list', 'https://example.test/list', 'ips', 'test', fn () => []);

    expect($fetch())->toBe([]);
    expect($fetch())->toBe([]);
    Http::assertSentCount(1);

    TestTime::addSeconds(RemoteListCache::REFRESH_RETRY_AFTER + 1);

    $fetch();
    Http::assertSentCount(2);
});

test('a stale source is refreshed once in the background', function () {
    app(StorageDriver::class)->set('abuseip-list', [
        'ips' => [350046382],
        'updated_at' => now()->subDays(4)->timestamp,
    ]);

    $remoteListCache = app(RemoteListCache::class);

    foreach (range(1, 3) as $i) {
        expect($remoteListCache->get('abuseip-list', 'https://example.test/list', 'ips', 'test', fn () => []))
            ->toBe([350046382]);
    }

    expect(app(DeferredCallbackCollection::class))->toHaveCount(1);
});
