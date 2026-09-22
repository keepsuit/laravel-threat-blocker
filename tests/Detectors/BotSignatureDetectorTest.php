<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;

beforeEach(function () {
    config()->set('threat-blocker.detectors', [
        BotSignatureDetector::class => [],
    ]);
});

function botSignatureDetector(): BotSignatureDetector
{
    return app(ThreatBlocker::class)->getDetector(BotSignatureDetector::class);
}

function useBotSignatureRules(array $rules): void
{
    config()->set('threat-blocker.detectors', [
        BotSignatureDetector::class => ['rules' => $rules],
    ]);
}

test('registers the bot signature detector', function () {
    expect(botSignatureDetector())
        ->toBeInstanceOf(BotSignatureDetector::class);
});

test('blocks a known bot user agent on post requests', function () {
    $request = Request::create('/contact', 'POST');
    $request->headers->set('User-Agent', 'curl/8.10.1');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Known bot User-Agent detected.');
});

test('skips bot signature checks for non-post requests', function () {
    $request = Request::create('/contact', 'GET');
    $request->headers->set('User-Agent', 'curl/8.10.1');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('blocks a missing user agent by default', function () {
    $request = Request::create('/contact', 'POST');
    $request->headers->remove('User-Agent');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Missing User-Agent detected.');
});

test('allows a missing user agent when that rule is disabled', function () {
    useBotSignatureRules([
        'missing_user_agent' => false,
        'known_bot_user_agents' => false,
    ]);
    $request = Request::create('/contact', 'POST');
    $request->headers->remove('User-Agent');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('allows a known bot user agent when that rule is disabled', function () {
    useBotSignatureRules([
        'missing_user_agent' => false,
        'known_bot_user_agents' => false,
    ]);
    $request = Request::create('/contact', 'POST');
    $request->headers->set('User-Agent', 'curl/8.10.1');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('blocks a missing accept language when enabled', function () {
    useBotSignatureRules([
        'missing_accept_language' => true,
    ]);
    $request = Request::create('/contact', 'POST');
    $request->headers->set('User-Agent', 'Mozilla/5.0');
    $request->headers->remove('Accept-Language');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Missing Accept-Language detected.');
});

test('allows a missing accept language when disabled', function () {
    $request = Request::create('/contact', 'POST');
    $request->headers->set('User-Agent', 'Mozilla/5.0');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('blocks a missing referer when enabled', function () {
    useBotSignatureRules([
        'invalid_referer' => true,
    ]);
    $request = Request::create('https://example.test/contact', 'POST');
    $request->headers->remove('Referer');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Invalid Referer detected.');
});

test('allows an invalid referer when the rule is disabled', function () {
    $request = Request::create('https://example.test/contact', 'POST');
    $request->headers->set('Referer', 'https://other.test/form');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('blocks a referer from another host when enabled', function () {
    useBotSignatureRules([
        'invalid_referer' => true,
    ]);
    $request = Request::create('https://example.test/contact', 'POST');
    $request->headers->set('Referer', 'https://other.test/form');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Invalid Referer detected.');
});

test('allows a same-host referer regardless of scheme and port', function () {
    useBotSignatureRules([
        'invalid_referer' => true,
    ]);
    $request = Request::create('https://example.test/contact', 'POST');
    $request->headers->set('Referer', 'http://example.test:8443/form');

    expect(fn () => botSignatureDetector()->check($request))
        ->not->toThrow(ThreatDetectedException::class);
});

test('blocks a malformed referer when enabled', function () {
    useBotSignatureRules([
        'invalid_referer' => true,
    ]);
    $request = Request::create('https://example.test/contact', 'POST');
    $request->headers->set('Referer', 'not a url');

    expect(fn () => botSignatureDetector()->check($request))
        ->toThrow(ThreatDetectedException::class, 'Invalid Referer detected.');
});

test('exposes the conservative default user agent patterns', function () {
    expect(BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS)->toBe([
        '/curl/i',
        '/python-requests/i',
        '/Go-http-client/i',
        '/libwww/i',
        '/Scrapy/i',
        '/wget/i',
        '/HTTPie/i',
        '/okhttp/i',
    ]);
});

test('custom user agent patterns replace the defaults', function () {
    config()->set('threat-blocker.detectors', [
        BotSignatureDetector::class => [
            'user_agent_patterns' => ['/custom-client/i'],
        ],
    ]);

    $detector = botSignatureDetector();
    $curlRequest = Request::create('/contact', 'POST');
    $curlRequest->headers->set('User-Agent', 'curl/8.10.1');
    $customRequest = Request::create('/contact', 'POST');
    $customRequest->headers->set('User-Agent', 'custom-client/1.0');

    expect(fn () => $detector->check($curlRequest))
        ->not->toThrow(ThreatDetectedException::class);
    expect(fn () => $detector->check($customRequest))
        ->toThrow(ThreatDetectedException::class);
});

test('custom user agent patterns can extend the defaults', function () {
    config()->set('threat-blocker.detectors', [
        BotSignatureDetector::class => [
            'user_agent_patterns' => array_merge(
                BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS,
                ['/custom-client/i'],
            ),
        ],
    ]);

    $detector = botSignatureDetector();
    $customRequest = Request::create('/contact', 'POST');
    $customRequest->headers->set('User-Agent', 'custom-client/1.0');

    expect(fn () => $detector->check($customRequest))
        ->toThrow(ThreatDetectedException::class);
});

test('logs and skips malformed user agent patterns', function () {
    Log::shouldReceive('warning')
        ->once()
        ->withArgs(fn (string $message, array $context): bool => $message ===
            'BotSignatureDetector: invalid User-Agent pattern skipped.'
            && $context['pattern'] === '/[/'
        )
        ->andReturnNull();

    config()->set('threat-blocker.detectors', [
        BotSignatureDetector::class => [
            'user_agent_patterns' => ['/[/', '/valid-client/i'],
        ],
    ]);

    $detector = botSignatureDetector();
    $request = Request::create('/contact', 'POST');
    $request->headers->set('User-Agent', 'valid-client/1.0');

    expect(fn () => $detector->check($request))
        ->toThrow(ThreatDetectedException::class);
});
