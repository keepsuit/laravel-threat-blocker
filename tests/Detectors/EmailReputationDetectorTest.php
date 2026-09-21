<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Keepsuit\ThreatBlocker\Contracts\DnsResolver;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;

beforeEach(function () {
    config()->set('threat-blocker.detectors', [
        EmailReputationDetector::class => [
            'source' => 'https://example.test/disposable-domains.txt',
            'check_mx' => false,
        ],
    ]);

    Http::fake([
        'https://example.test/disposable-domains.txt' => Http::response("blocked.example\n"),
    ]);
});

test('registers the email reputation detector', function () {
    expect(app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class))
        ->toBeInstanceOf(EmailReputationDetector::class);
});

test('matches a configured field by its terminal name in nested input', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.fields',
        ['email'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'contacts' => [
            ['email' => 'user@blocked.example'],
        ],
    ])))
        ->toThrow(ThreatDetectedException::class);
});

test('matches terminal field names with a wildcard', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.fields',
        ['email_*'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'profile' => [
            'email_primary' => 'user@blocked.example',
        ],
    ])))
        ->toThrow(ThreatDetectedException::class);
});

test('matches a dotted wildcard field path', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.fields',
        ['contacts.*.email'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'contacts' => [
            ['email' => 'user@blocked.example'],
        ],
    ])))
        ->toThrow(ThreatDetectedException::class);
});

test('ignores non-string and invalid matched values', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.fields',
        ['email'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'email' => [123, 'not-an-email'],
    ])))->not->toThrow(ThreatDetectedException::class);

    Http::assertNothingSent();
});

test('whitelisted domains bypass the other reputation checks', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.whitelist',
        ['blocked.example'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'email' => 'user@blocked.example',
    ])))->not->toThrow(ThreatDetectedException::class);

    Http::assertNothingSent();
});

test('blacklisted domains are checked before the remote source', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.blacklist',
        ['blocked.example'],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'email' => 'user@blocked.example',
    ])))->toThrow(ThreatDetectedException::class);

    Http::assertNothingSent();
});

test('updates and caches the disposable domain source', function () {
    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    $detector?->updateSource();

    expect(app(StorageDriver::class)->get(EmailReputationDetector::LIST_CACHE_KEY))
        ->toMatchArray([
            'domains' => ['blocked.example'],
        ])
        ->updated_at->toBeInt();
});

test('blocks domains without an MX record and caches the DNS result', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.check_mx',
        true,
    );

    $resolver = new class implements DnsResolver
    {
        public int $calls = 0;

        public function hasMxRecord(string $domain): bool
        {
            $this->calls++;

            return false;
        }
    };

    app()->bind(DnsResolver::class, fn () => $resolver);

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);
    $request = Request::create('/register', 'POST', ['email' => 'user@deliverability.example']);

    expect(fn () => $detector?->check($request))->toThrow(ThreatDetectedException::class);
    expect(fn () => $detector?->check($request))->toThrow(ThreatDetectedException::class);
    expect($resolver->calls)->toBe(1);
});

test('does not resolve MX when the disposable list already matches', function () {
    $resolver = new class implements DnsResolver
    {
        public int $calls = 0;

        public function hasMxRecord(string $domain): bool
        {
            $this->calls++;

            return true;
        }
    };

    app()->bind(DnsResolver::class, fn () => $resolver);

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'email' => 'user@blocked.example',
    ])))->toThrow(ThreatDetectedException::class);
    expect($resolver->calls)->toBe(0);
});

test('skips email checks when no fields are configured', function () {
    config()->set(
        'threat-blocker.detectors.'.EmailReputationDetector::class.'.fields',
        [],
    );

    $detector = app(ThreatBlocker::class)->getDetector(EmailReputationDetector::class);

    expect(fn () => $detector?->check(Request::create('/register', 'POST', [
        'email' => 'user@blocked.example',
    ])))->not->toThrow(ThreatDetectedException::class);
});
