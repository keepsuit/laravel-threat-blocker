<?php

use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Middleware\ProtectAgainstThreat;

use function Pest\Laravel\get;
use function Pest\Laravel\withServerVariables;

beforeEach(function () {
    app(StorageDriver::class)->set(\Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::LIST_CACHE_KEY, [
        ip2long('1.0.170.118'),
    ]);

    Route::any('test', function () {
        return 'ok';
    })->middleware(ProtectAgainstThreat::class);
});

test('safe request pass checks', function () {
    get('/test')
        ->assertOk()
        ->assertSee('ok');
});

it('block request from abused ip', function () {
    withServerVariables(['REMOTE_ADDR' => '1.0.170.118'])
        ->get('/test')
        ->assertForbidden()
        ->assertDontSee('ok');
});
