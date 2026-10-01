<?php

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\AiSpamDetector;
use Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;
use Keepsuit\ThreatBlocker\Support\RequestMethods;
use Keepsuit\ThreatBlocker\ThreatBlocker;

test('resolves methods', function (array $options, bool $bodyOnly, array $expected) {
    expect(RequestMethods::resolve($options, $bodyOnly))->toBe($expected);
})->with([
    'default' => [[], false, ['POST']],
    'normalizes case, duplicates and non strings' => [['methods' => ['post', 'POST', 1, 'get']], false, ['POST', 'GET']],
    'wildcard' => [['methods' => ['*']], false, ['*']],
    'not an array' => [['methods' => 'POST'], false, []],
    'body detectors ignore unsupported methods' => [['methods' => ['GET', 'delete', 'patch']], true, ['PATCH']],
    'body detectors expand the wildcard' => [['methods' => ['*']], true, ['POST', 'PUT', 'PATCH']],
    'body detectors may end up with no methods' => [['methods' => ['GET']], true, []],
]);

test('matches the request method', function () {
    expect(RequestMethods::matches(['POST'], Request::create('/', 'POST')))->toBeTrue()
        ->and(RequestMethods::matches(['POST'], Request::create('/', 'GET')))->toBeFalse()
        ->and(RequestMethods::matches(['*'], Request::create('/', 'DELETE')))->toBeTrue()
        ->and(RequestMethods::matches([], Request::create('/', 'POST')))->toBeFalse();
});

test('detectors use the global methods', function () {
    config()->set('threat-blocker.methods', ['PUT']);
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => [],
        BotSignatureDetector::class => [],
        EmailReputationDetector::class => [],
    ]);

    $blocker = app(ThreatBlocker::class);

    expect(invade($blocker->getDetector(AbuseIpDetector::class))->methods)->toBe(['PUT'])
        ->and(invade($blocker->getDetector(BotSignatureDetector::class))->methods)->toBe(['PUT'])
        ->and(invade($blocker->getDetector(EmailReputationDetector::class))->methods)->toBe(['PUT']);
});

test('detector methods override the global ones', function () {
    config()->set('threat-blocker.methods', ['POST']);
    config()->set('threat-blocker.detectors', [
        AbuseIpDetector::class => ['methods' => ['*']],
        BotSignatureDetector::class => ['methods' => ['GET']],
        AiSpamDetector::class => ['methods' => ['GET', 'PUT']],
    ]);

    $blocker = app(ThreatBlocker::class);

    expect(invade($blocker->getDetector(AbuseIpDetector::class))->methods)->toBe(['*'])
        ->and(invade($blocker->getDetector(BotSignatureDetector::class))->methods)->toBe(['GET'])
        ->and(invade($blocker->getDetector(AiSpamDetector::class))->methods)->toBe(['PUT']);
});

test('detector ids are kebab cased', function () {
    expect(ThreatBlocker::idFor(AbuseIpDetector::class))->toBe('abuse-ip')
        ->and(ThreatBlocker::idFor(BotSignatureDetector::class))->toBe('bot-signature')
        ->and(ThreatBlocker::idFor(EmailReputationDetector::class))->toBe('email-reputation')
        ->and(ThreatBlocker::idFor(AiSpamDetector::class))->toBe('ai-spam');
});
