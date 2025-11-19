<?php

use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Middleware\ProtectAgainstThreats;
use Spatie\Honeypot\EncryptedTime;
use Spatie\TestTime\TestTime;

use function Pest\Laravel\get;
use function Pest\Laravel\post;
use function Pest\Laravel\withServerVariables;

beforeEach(function () {
    TestTime::freeze('Y-m-d H:i:s', '2025-01-01 00:00:00');

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
        ->assertOk()
        ->assertDontSee('ok');
});

it('block request from blacklist', function () {
    config()->set('threat-blocker.detectors.Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector.blacklist', [
        '10.10.10.10',
    ]);

    withServerVariables(['REMOTE_ADDR' => '10.10.10.10'])
        ->get('/test')
        ->assertOk()
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

it('blocks form submissions with honeypot filled (not randomized)', function () {
    $nameField = config('honeypot.name_field_name');
    config()->set('honeypot.randomize_name_field_name', false);

    post('/test', [
        $nameField => 'My name',
        'other' => 'value',
    ])
        ->assertOk()
        ->assertDontSee('ok');
});

it('blocks form submissions with honeypot filled (randomized)', function () {
    $nameField = config('honeypot.name_field_name').'-'.Str::random();
    config()->set('honeypot.randomize_name_field_name', true);

    post('/test', [
        $nameField => 'My name',
        'other' => 'value',
    ])
        ->assertOk()
        ->assertDontSee('ok');
});

it('blocks form submissions too fast', function () {
    config()->set('honeypot.randomize_name_field_name', false);

    $nameField = config('honeypot.name_field_name');
    $validFromField = config('honeypot.valid_from_field_name');
    $validFrom = EncryptedTime::create(now()->addSecond());

    post('/test', [
        $validFromField => $validFrom,
        $nameField => 'My name',
        'other' => 'value',
    ])
        ->assertOk()
        ->assertDontSee('ok');
});

it('allows form submissions without honeypot filled', function () {
    config()->set('honeypot.honeypot_fields_required_for_all_forms', true);

    post('/test', [
        'other' => 'value',
    ])
        ->assertOk()
        ->assertSee('ok');
});
