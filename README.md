# Block threat request to your application

[![Latest Version on Packagist](https://img.shields.io/packagist/v/keepsuit/laravel-threat-blocker.svg?style=flat-square)](https://packagist.org/packages/keepsuit/laravel-threat-blocker)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/keepsuit/laravel-threat-blocker/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/keepsuit/laravel-threat-blocker/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/keepsuit/laravel-threat-blocker/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/keepsuit/laravel-threat-blocker/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/keepsuit/laravel-threat-blocker.svg?style=flat-square)](https://packagist.org/packages/keepsuit/laravel-threat-blocker)

Laravel Threat Blocker is a package to block threat requests to your Laravel application based on different rules.

## Installation

You can install the package via composer:

```bash
composer require keepsuit/laravel-threat-blocker
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="laravel-threat-blocker-config"
```

This is the contents of the published config file:

```php
return [
    /**
     * This option enables or disables the Threat Blocker protection.
     */
    'enabled' => env('THREAT_BLOCKER_ENABLED', true),

    /**
     * Log a warning when a threat is detected.
     */
    'log' => env('THREAT_BLOCKER_LOG_ENABLED', false),

    /**
     * HTTP methods checked by the detectors, '*' means any method.
     * Each detector can override it with its own 'methods' option.
     * Detectors that inspect the request body (FormHoneypotDetector, AiSpamDetector,
     * EmailReputationDetector) only support POST, PUT and PATCH, other methods are ignored.
     */
    'methods' => ['POST'],

    /**
     * Storage driver to use for caching detectors data.
     */
    'storage_driver' => env('THREAT_BLOCKER_STORAGE_DRIVER', 'cache'),

    'storage' => [
        'cache' => [
            'store' => env('THREAT_BLOCKER_CACHE_STORE', env('CACHE_STORE', 'file')),
            'prefix' => env('THREAT_BLOCKER_CACHE_PREFIX', 'threat_blocker'),
        ],
    ],

    /**
     * The following list of "detectors" will be used to identify threats.
     * You can enable or disable each detector individually and configure their settings.
     */
    'detectors' => [
        /**
         * Block requests coming from IPs listed in the AbuseIPDB database.
         */
        \Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector::class => [
            'enabled' => env('THREAT_BLOCKER_ABUSE_IP_DETECTOR_ENABLED', true),
            // Source url for AbuseIP data, it can be a custom url or one of the predefined sources (provided by https://github.com/borestad/blocklist-abuseipdb)
            'source' => \Keepsuit\ThreatBlocker\Enums\AbuseIpSource::Days30->url(),
            'blacklist' => [
                // These IPs will always be blocked by the AbuseIpDetector
            ],
            'whitelist' => [
                // These IPs will never be blocked by the AbuseIpDetector
                '127.0.0.1',
            ],
        ],
        /**
         * Block registrations using disposable or undeliverable email domains.
         */
        \Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector::class => [
            'enabled' => env('THREAT_BLOCKER_EMAIL_REPUTATION_DETECTOR_ENABLED', true),
            // Source URL for the disposable email domain list, one domain per line.
            'source' => \Keepsuit\ThreatBlocker\Enums\EmailReputationSource::DisposableEmailDomains->url(),
            // Empty fields disable this detector. `email` also matches nested terminal fields;
            // use patterns such as `contacts.*.email` for a specific nested path.
            'fields' => ['email'],
            'check_mx' => true,
            'mx_cache_ttl' => 86400,
            'blacklist' => [],
            'whitelist' => [],
        ],
        /**
         * Block POST requests that look like automated form submissions based on their headers.
         */
        \Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector::class => [
            'enabled' => env('THREAT_BLOCKER_BOT_SIGNATURE_DETECTOR_ENABLED', true),
            'rules' => [
                'missing_user_agent' => true,
                'known_bot_user_agents' => true,
                'missing_accept_language' => false,
                'invalid_referer' => false,
            ],
            // Replace the defaults, or use array_merge() to extend them.
            'user_agent_patterns' => \Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS,
        ],
        /**
         * Block requests that contain form submissions with honeypot fields filled out.
         * This detector requires spatie/laravel-honeypot package to be installed and configured.
         */
        \Keepsuit\ThreatBlocker\Detectors\FormHoneypotDetector::class => [
            'enabled' => env('THREAT_BLOCKER_FORM_HONEYPOT_DETECTOR_ENABLED', true),
            // Require honeypot fields on every POST request or selected URI patterns.
            // Examples: true, ['/contact', '/newsletter/*']
            'strict' => false,
        ],
        /**
         * Block POST requests classified as spam or phishing by an AI model.
         */
        \Keepsuit\ThreatBlocker\Detectors\AiSpamDetector::class => [
            'enabled' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_ENABLED', false),
            'provider' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_PROVIDER'),
            'model' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_MODEL'),
            'fields' => ['*'],
            'only' => [],
            'context' => [],
            'threshold' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_THRESHOLD', 0.8),
            'max_length' => 4000,
            'timeout' => 5,
        ],
    ],
];
```

`EmailReputationSource` provides built-in disposable-domain list URLs for the default,
DNS-validated, curated, and high-coverage sources. The `source` option also accepts any
custom URL serving one domain per line.

`BotSignatureDetector` reads only the request headers, so it can run on any method. Each configured rule is independent:

- `missing_user_agent` blocks missing or blank User-Agent headers.
- `known_bot_user_agents` matches the configurable case-insensitive PCRE patterns.
- `missing_accept_language` blocks missing or blank Accept-Language headers.
- `invalid_referer` blocks missing, malformed, or cross-host Referer headers.

The default User-Agent patterns are conservative and available through
`BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS`. Supplying `user_agent_patterns`
replaces them; extend them with `array_merge()` when needed. Crawler and link-preview
identities such as Googlebot, bingbot, Slackbot, and Discordbot are intentionally not
included in the defaults.

`AiSpamDetector` classifies form data as legitimate, spam or phishing with
[`laravel/ai`](https://github.com/laravel/ai). It is disabled by default and needs
`composer require laravel/ai` plus the API key of a provider that supports classification
(only `typesafe` and `openrouter` do). Every evaluated request adds latency and provider cost,
so restrict it with `only` and keep it last in the detectors list.

- Form data is sent to the external provider. Files, `_token`, `_method` and password fields
  are never sent, and the payload is truncated to `max_length` characters.
- A request is blocked when the spam + phishing probability reaches `threshold`. Providers that
  return no probabilities never block.
- On any provider error or timeout the request is allowed and a warning is logged (fail-open).
- `context` maps URI patterns to extra instructions, appended to the default ones:

```php
'only' => ['/contact', '/quote/*'],
'context' => [
    '/quote/*' => 'This form receives quote requests for industrial machinery.',
],
```

Models verified with the live tests on OpenRouter: `~typesafe/jev-latest`, `inception/mercury-decide:free`.

Tested but not recommended: `togethercomputer/tev1-4b-experimental` and `jaredpalmer/kev-4b` fail some live tests or score close to the `threshold`.
`respan/span-01` and `respan/span-01-lite` do not work: they only support Noul (yes/no) questions and return an error for the `Choice` question the detector asks.

## HTTP methods

Detectors run only on the methods listed in the global `methods` option (default `['POST']`),
and `*` means any method. A detector can override it with its own `methods` option:

```php
'methods' => ['POST'],

'detectors' => [
    AbuseIpDetector::class => [
        'methods' => ['*'],
    ],
],
```

`FormHoneypotDetector`, `AiSpamDetector` and `EmailReputationDetector` inspect the request body, so they
only support `POST`, `PUT` and `PATCH`: any other configured method is ignored. An empty list means the
detector never runs; use `'enabled' => false` to turn it off.

## Detections

Detectors report a threat by throwing `ThreatDetectedException`, which exposes the `detectorId`
(e.g. `bot-signature`) and a `context` array with details about the detection. The message is prefixed with
the detector id (`[bot-signature] Known bot User-Agent detected.`).

The `ThreatDetectedEvent` event carries the `request` and the `exception`. Detectors put in the
context only derived values (category, score, domain), never request content or full email addresses.

Set `THREAT_BLOCKER_LOG_ENABLED=true` to log every detection as a warning with the request method, path, IP
and the exception context.

## Usage

1. Add the `ProtectAgainstThreats` middleware to routes you want to protect:

    ```php
    use Keepsuit\ThreatBlocker\Middleware\ProtectAgainstThreats;
    
    Route::post('contact', [ContactController::class, 'submit'])->middleware(ProtectAgainstThreats::class);
    ```

2. Run the update command to warm the detectors cache:

    ```bash
    php artisan threat-blocker:update
    ```

3. Schedule the update command to run periodically (e.g., daily) using Laravel's task scheduling:

    ```php
    $schedule->command('threat-blocker:update')->daily();
    ```

## Testing

```bash
composer test
```

Live tests that call the real provider are excluded from the default run. Run them with
`vendor/bin/pest --group=live` with `TYPESAFE_API_KEY` (or `OPENROUTER_API_KEY`) set in the shell or in the package `.env`; without a key they are skipped.
`THREAT_BLOCKER_AI_SPAM_DETECTOR_PROVIDER` and `THREAT_BLOCKER_AI_SPAM_DETECTOR_MODEL` select another provider or model.

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Credits

- [Fabio Capucci](https://github.com/keepsuit)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
