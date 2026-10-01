<?php

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\AiSpamDetector;
use Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;
use Keepsuit\ThreatBlocker\Enums\HttpMethod;
use Keepsuit\ThreatBlocker\ThreatBlocker;

test('resolves methods', function (array $options, bool $bodyOnly, array $expected) {
    expect(HttpMethod::fromOptions($options, $bodyOnly))->toBe($expected);
})->with([
    'default' => [[], false, [HttpMethod::Post]],
    'normalizes case, duplicates and invalid values' => [['methods' => ['post', 'POST', 1, 'get', 'foo']], false, [HttpMethod::Post, HttpMethod::Get]],
    'accepts enum cases' => [['methods' => [HttpMethod::Put, 'put']], false, [HttpMethod::Put]],
    'wildcard' => [['methods' => ['*']], false, HttpMethod::cases()],
    'single method' => [['methods' => 'put'], false, [HttpMethod::Put]],
    'body detectors ignore unsupported methods' => [['methods' => ['GET', 'delete', 'patch']], true, [HttpMethod::Patch]],
    'body detectors expand the wildcard' => [['methods' => ['*']], true, [HttpMethod::Post, HttpMethod::Put, HttpMethod::Patch]],
    'body detectors may end up with no methods' => [['methods' => ['GET']], true, []],
]);

test('matches the request method', function () {
    expect(HttpMethod::matches([HttpMethod::Post], Request::create('/', 'POST')))->toBeTrue()
        ->and(HttpMethod::matches([HttpMethod::Post], Request::create('/', 'GET')))->toBeFalse()
        ->and(HttpMethod::matches([], Request::create('/', 'POST')))->toBeFalse()
        ->and(HttpMethod::matches(HttpMethod::cases(), Request::create('/', 'PROPFIND')))->toBeFalse();
});

test('detectors use the global methods', function () {
    config()->set('threat-blocker.methods', ['PUT']);
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => [],
        BotSignatureDetector::class => [],
        EmailReputationDetector::class => [],
    ]);

    $blocker = app(ThreatBlocker::class);

    expect(invade($blocker->getDetector(AbuseIpDetector::class))->methods)->toBe([HttpMethod::Put])
        ->and(invade($blocker->getDetector(BotSignatureDetector::class))->methods)->toBe([HttpMethod::Put])
        ->and(invade($blocker->getDetector(EmailReputationDetector::class))->methods)->toBe([HttpMethod::Put]);
});

test('detector methods override the global ones', function () {
    config()->set('threat-blocker.methods', ['POST']);
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => ['methods' => ['*']],
        BotSignatureDetector::class => ['methods' => ['GET']],
        AiSpamDetector::class => ['methods' => ['GET', 'PUT']],
    ]);

    $blocker = app(ThreatBlocker::class);

    expect(invade($blocker->getDetector(AbuseIpDetector::class))->methods)->toBe(HttpMethod::cases())
        ->and(invade($blocker->getDetector(BotSignatureDetector::class))->methods)->toBe([HttpMethod::Get])
        ->and(invade($blocker->getDetector(AiSpamDetector::class))->methods)->toBe([HttpMethod::Put]);
});

test('detectors expose a stable id', function () {
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => [],
        BotSignatureDetector::class => [],
        EmailReputationDetector::class => [],
        AiSpamDetector::class => [],
    ]);

    $blocker = app(ThreatBlocker::class);

    expect($blocker->getDetectorById('abuse-ip'))->toBeInstanceOf(AbuseIpDetector::class)
        ->and($blocker->getDetectorById('bot-signature'))->toBeInstanceOf(BotSignatureDetector::class)
        ->and($blocker->getDetectorById('email-reputation'))->toBeInstanceOf(EmailReputationDetector::class)
        ->and($blocker->getDetectorById('ai-spam'))->toBeInstanceOf(AiSpamDetector::class);
});
