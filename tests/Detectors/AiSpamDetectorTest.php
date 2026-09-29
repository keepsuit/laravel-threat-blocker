<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Detectors\AiSpamDetector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;
use Laravel\Ai\Classification;
use Laravel\Ai\Prompts\ClassificationPrompt;
use Laravel\Ai\Responses\Data\ChoiceAnswer;

function useAiSpamOptions(array $options = []): void
{
    config()->set('threat-blocker.detectors', [
        AiSpamDetector::class => $options,
    ]);
}

function aiSpamDetector(): AiSpamDetector
{
    return app(ThreatBlocker::class)->getDetector(AiSpamDetector::class);
}

function fakeAiCategory(array $probabilities): void
{
    Classification::fake([
        ['category' => new ChoiceAnswer(array_search(max($probabilities), $probabilities), $probabilities)],
    ])->preventStrayClassifications();
}

function aiSpamPost(array $input = ['message' => 'Hello there'], string $uri = '/contact'): Request
{
    return Request::create($uri, 'POST', $input);
}

test('blocks when spam and phishing reach the threshold', function () {
    useAiSpamOptions();
    fakeAiCategory(['legitimate' => 0.1, 'spam' => 0.9, 'phishing' => 0.0]);

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->toThrow(ThreatDetectedException::class, 'AiSpamDetector flagged request as spam (spam+phishing 0.9).');
});

test('blocks when spam and phishing are split', function () {
    useAiSpamOptions();
    fakeAiCategory(['legitimate' => 0.1, 'spam' => 0.45, 'phishing' => 0.45]);

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->toThrow(ThreatDetectedException::class, 'spam+phishing 0.9');
});

test('labels the request with the most likely threat', function () {
    useAiSpamOptions();
    fakeAiCategory(['legitimate' => 0.1, 'spam' => 0.2, 'phishing' => 0.7]);

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->toThrow(ThreatDetectedException::class, 'flagged request as phishing');
});

test('allows below the threshold', function () {
    useAiSpamOptions();
    fakeAiCategory(['legitimate' => 0.3, 'spam' => 0.4, 'phishing' => 0.3]);

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->not->toThrow(ThreatDetectedException::class);
});

test('honors a custom threshold', function () {
    useAiSpamOptions(['threshold' => 0.5]);
    fakeAiCategory(['legitimate' => 0.4, 'spam' => 0.6, 'phishing' => 0.0]);

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->toThrow(ThreatDetectedException::class);
});

test('allows when the provider returns no probabilities', function () {
    useAiSpamOptions();
    fakeAiCategory([]);
    Classification::fake([
        ['category' => new ChoiceAnswer('spam', [])],
    ])->preventStrayClassifications();

    expect(fn () => aiSpamDetector()->check(aiSpamPost()))
        ->not->toThrow(ThreatDetectedException::class);
});

test('does not classify non-post requests', function () {
    useAiSpamOptions();
    Classification::fake()->preventStrayClassifications();

    aiSpamDetector()->check(Request::create('/contact', 'GET', ['message' => 'Hello']));

    Classification::assertNothingClassified();
});

test('does not classify uris outside the only patterns', function () {
    useAiSpamOptions(['only' => ['/contact']]);
    Classification::fake()->preventStrayClassifications();

    aiSpamDetector()->check(aiSpamPost(uri: '/newsletter'));

    Classification::assertNothingClassified();
});

test('classifies uris matching the only patterns', function () {
    useAiSpamOptions(['only' => ['/contact']]);
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost());

    Classification::assertClassified(fn (ClassificationPrompt $prompt) => $prompt->asks('category'));
});

test('does not classify with empty fields', function () {
    useAiSpamOptions(['fields' => []]);
    Classification::fake()->preventStrayClassifications();

    aiSpamDetector()->check(aiSpamPost());

    Classification::assertNothingClassified();
});

test('sends only the configured fields', function () {
    useAiSpamOptions(['fields' => ['message']]);
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost(['message' => 'Hello', 'name' => 'Mario', 'nested' => ['message' => 'Hi']]));

    Classification::assertClassified(
        fn (ClassificationPrompt $prompt) => $prompt->state === ['message' => 'Hello', 'nested.message' => 'Hi']
    );
});

test('excludes sensitive keys from the state', function () {
    useAiSpamOptions();
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost([
        '_token' => 'csrf',
        '_method' => 'POST',
        'password' => 'secret',
        'password_confirmation' => 'secret',
        'current_password' => 'secret',
        'user' => ['password' => 'secret'],
        'message' => 'Hello',
    ]));

    Classification::assertClassified(
        fn (ClassificationPrompt $prompt) => $prompt->state === ['message' => 'Hello']
    );
});

test('truncates the state to max_length', function () {
    useAiSpamOptions(['max_length' => 10]);
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost(['a' => 'èèèèèèèè', 'b' => 'èèèèèèèè', 'c' => 'ignored']));

    Classification::assertClassified(
        fn (ClassificationPrompt $prompt) => $prompt->state === ['a' => 'èèèèèèèè', 'b' => 'èè']
    );
});

test('does not classify a blank state', function () {
    useAiSpamOptions();
    Classification::fake()->preventStrayClassifications();

    aiSpamDetector()->check(aiSpamPost(['_token' => 'csrf', 'message' => '  ']));

    Classification::assertNothingClassified();
});

test('appends the matching context to the default instructions', function () {
    useAiSpamOptions(['context' => ['/quote/*' => 'Quote requests for machinery.']]);
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost(uri: '/quote/new'));

    Classification::assertClassified(
        fn (ClassificationPrompt $prompt) => str_starts_with($prompt->questions['category']->instructions, AiSpamDetector::DEFAULT_INSTRUCTIONS)
            && str_ends_with($prompt->questions['category']->instructions, 'Quote requests for machinery.')
    );
});

test('uses only the default instructions when no context matches', function () {
    useAiSpamOptions(['context' => ['/quote/*' => 'Quote requests for machinery.']]);
    fakeAiCategory(['legitimate' => 1.0, 'spam' => 0.0, 'phishing' => 0.0]);

    aiSpamDetector()->check(aiSpamPost());

    Classification::assertClassified(
        fn (ClassificationPrompt $prompt) => $prompt->questions['category']->instructions === AiSpamDetector::DEFAULT_INSTRUCTIONS
    );
});

test('allows and logs a warning without the payload when classification fails', function () {
    useAiSpamOptions();
    Classification::fake(fn () => throw new RuntimeException('Provider down'))->preventStrayClassifications();

    Log::spy();

    expect(fn () => aiSpamDetector()->check(aiSpamPost(['message' => 'top secret payload'])))
        ->not->toThrow(Throwable::class);

    Log::shouldHaveReceived('warning')
        ->once()
        ->withArgs(fn (string $message, array $context) => $message === 'AiSpamDetector: classification failed, request allowed.'
            && $context === ['exception' => RuntimeException::class, 'message' => 'Provider down']);
});
