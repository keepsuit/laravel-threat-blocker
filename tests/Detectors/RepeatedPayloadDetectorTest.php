<?php

use Illuminate\Testing\TestResponse;
use Keepsuit\ThreatBlocker\Detectors\RepeatedPayloadDetector;
use Keepsuit\ThreatBlocker\Middleware\ProtectAgainstThreats;
use Spatie\TestTime\TestTime;

use function Pest\Laravel\post;
use function Pest\Laravel\withServerVariables;

beforeEach(function () {
    TestTime::freeze('Y-m-d H:i:s', '2025-01-01 00:00:00');

    config()->set('honeypot.enabled', false);
    config()->set('threat-blocker.detectors.'.RepeatedPayloadDetector::class, [
        'window' => 3600,
        'threshold' => 3,
        'paths' => [
            'register' => ['first_name', 'last_name', 'phone'],
        ],
    ]);

    Route::any('{path}', fn () => 'ok')->where('path', '.*')->middleware(ProtectAgainstThreats::class);
});

/**
 * The registration bot this detector was written for: one static payload, a fresh email
 * and a fresh source address on every submission.
 */
function spamSubmission(int $attempt): TestResponse
{
    return withServerVariables(['REMOTE_ADDR' => '10.0.0.'.$attempt])
        ->post('/register', [
            'first_name' => 'Test',
            'last_name' => 'User',
            'phone' => '+79990000000',
            'email' => sprintf('victim%d@example.com', $attempt),
        ]);
}

it('blocks a payload repeated over the threshold', function () {
    foreach (range(1, 3) as $attempt) {
        spamSubmission($attempt)->assertSee('ok');
    }

    spamSubmission(4)->assertDontSee('ok');
});

it('keeps blocking the payload for the rest of the window', function () {
    foreach (range(1, 4) as $attempt) {
        spamSubmission($attempt);
    }

    TestTime::addMinutes(59);

    spamSubmission(5)->assertDontSee('ok');
});

it('forgets the payload once the window is over', function () {
    foreach (range(1, 4) as $attempt) {
        spamSubmission($attempt);
    }

    TestTime::addHour();

    spamSubmission(5)->assertSee('ok');
});

it('allows distinct payloads from a single address', function () {
    foreach (range(1, 10) as $attempt) {
        withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
            ->post('/register', [
                'first_name' => 'Mario',
                'last_name' => 'Rossi'.$attempt,
                'phone' => '+3933300000'.$attempt,
                'email' => sprintf('mario%d@example.com', $attempt),
            ])
            ->assertSee('ok');
    }
});

it('ignores paths it was not pointed at', function () {
    foreach (range(1, 10) as $attempt) {
        post('/newsletter', [
            'first_name' => 'Test',
            'last_name' => 'User',
            'phone' => '+79990000000',
        ])->assertSee('ok');
    }
});

it('ignores submissions carrying none of the fingerprinted fields', function () {
    foreach (range(1, 10) as $attempt) {
        post('/register', ['email' => 'someone@example.com'])->assertSee('ok');
    }
});

it('tells payloads on different paths apart', function () {
    config()->set('threat-blocker.detectors.'.RepeatedPayloadDetector::class.'.paths', [
        'register' => ['first_name'],
        'contact' => ['first_name'],
    ]);

    foreach (range(1, 4) as $attempt) {
        post('/register', ['first_name' => 'Test']);
    }

    post('/contact', ['first_name' => 'Test'])->assertSee('ok');
});

it('does nothing when no path is configured', function () {
    config()->set('threat-blocker.detectors.'.RepeatedPayloadDetector::class.'.paths', []);

    foreach (range(1, 10) as $attempt) {
        spamSubmission($attempt)->assertSee('ok');
    }
});
