<?php

use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Middleware\ProtectAgainstThreats;

use function Pest\Laravel\get;
use function Pest\Laravel\withServerVariables;

beforeEach(function () {
    app(StorageDriver::class)->set(\Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::LIST_CACHE_KEY, [
        ip2long('1.0.170.118'),
    ]);

    Route::any('test', function () {
        return 'ok';
    })->middleware(ProtectAgainstThreats::class);
});

test('safe request pass checks', function () {
    get('/test')
        ->assertOk()
        ->assertSee('ok');
});

it('allow requests when disabled', function () {
    config()->set('threat-blocker.enabled', false);

    withServerVariables(['REMOTE_ADDR' => '1.0.170.118'])
        ->get('/test')
        ->assertOk()
        ->assertSee('ok');
});

it('block request from abused ip', function () {
    withServerVariables(['REMOTE_ADDR' => '1.0.170.118'])
        ->get('/test')
        ->assertForbidden()
        ->assertDontSee('ok');
});

it('block request from blacklist', function () {
    config()->set('threat-blocker.detectors.Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector.blacklist', [
        '10.10.10.10',
    ]);

    withServerVariables(['REMOTE_ADDR' => '10.10.10.10'])
        ->get('/test')
        ->assertForbidden()
        ->assertDontSee('ok');
});

it('allow request from whitelist', function () {
    config()->set('threat-blocker.detectors.Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector.whitelist', [
        '1.0.170.118',
    ]);

    withServerVariables(['REMOTE_ADDR' => '1.0.170.118'])
        ->get('/test')
        ->assertOk()
        ->assertSee('ok');
});
