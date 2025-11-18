<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;

beforeEach(function () {
    Http::fake([
        'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/*' => function ($request) {
            return Http::response(file_get_contents(__DIR__.'/stubs/abuseipdb-s100-1d.ipv4'));
        },
    ]);
});

test('updates abuse ip database from source url', function () {
    Artisan::call(\Keepsuit\ThreatBlocker\Commands\UpdateAbuseIpCommand::class);

    expect(app(StorageDriver::class)->get('abuseip-list'))
        ->toBeArray()
        ->toHaveCount(52204);
});
