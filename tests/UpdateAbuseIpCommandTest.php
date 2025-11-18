<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::fake([
        'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/*' => function ($request) {
            return Http::response(file_get_contents(__DIR__.'/stubs/abuseipdb-s100-1d.ipv4'));
        },
    ]);
});

test('updates abuse ip database from source url', function () {
    Artisan::call(\Keepsuit\ThreatBlocker\Commands\UpdateAbuseIpCommand::class);

    expect(Cache::get('threat-blocker:abuseip-list'))
        ->toBeArray()
        ->toHaveCount(52204);
});
