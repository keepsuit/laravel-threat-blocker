<?php

beforeEach(function () {
    config()->set('threat-blocker.detectors', [
        Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::class => true,
    ]);
});

test('register abuseip detector with default settings', function () {
    $detector = app(\Keepsuit\ThreatBlocker\ThreatBlocker::class)->getDetector(\Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::class);

    expect($detector)
        ->not->toBeNull()
        ->toBeInstanceOf(\Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::class);

    expect(invade($detector))
        ->sourceUrl->toBe(\Keepsuit\ThreatBlocker\Enums\AbuseIpSource::Days30->url())
        ->blacklistIps->toBe([])
        ->whitelistIps->toBe(['127.0.0.1']);
});
