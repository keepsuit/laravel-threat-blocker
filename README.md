# Block threat requests to your Laravel application

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

## Configuration

This is the contents of the published config file:

```php
<?php

use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\AiSpamDetector;
use Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;
use Keepsuit\ThreatBlocker\Detectors\FormHoneypotDetector;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
use Keepsuit\ThreatBlocker\Enums\EmailReputationSource;
use Keepsuit\ThreatBlocker\Responders\BlankPageResponder;

return [
    /**
     * This option enables or disables the Threat Blocker protection.
     */
    'enabled' => env('THREAT_BLOCKER_ENABLED', true),

    /**
     * HTTP methods checked by the detectors (names or HttpMethod cases), '*' means any method.
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
            'store' => env('THREAT_BLOCKER_CACHE_STORE', env('CACHE_STORE', env('CACHE_DRIVER', 'file'))),
            'prefix' => env('THREAT_BLOCKER_CACHE_PREFIX', 'threat_blocker'),
        ],
    ],

    /**
     * The responder class that will be used to respond to detected threats.
     * You can create your own responder by implementing the Keepsuit\ThreatBlocker\Contracts\ThreatResponder interface.
     */
    'responder' => BlankPageResponder::class,

    /**
     * The following list of "detectors" will be used to identify threats.
     * You can enable or disable each detector individually and configure their settings.
     */
    'detectors' => [
        /**
         * Block requests coming from IPs listed in the AbuseIPDB database.
         */
        AbuseIpDetector::class => [
            'enabled' => env('THREAT_BLOCKER_ABUSE_IP_DETECTOR_ENABLED', true),
            // Source url for AbuseIP data, it can be a custom url or one of the predefined sources (provided by https://github.com/borestad/blocklist-abuseipdb)
            'source' => AbuseIpSource::Days60->url(),
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
        EmailReputationDetector::class => [
            'enabled' => env('THREAT_BLOCKER_EMAIL_REPUTATION_DETECTOR_ENABLED', true),
            // Source URL for the disposable email domain list, one domain per line.
            'source' => EmailReputationSource::DisposableEmailDomains->url(),
            // Empty fields disable this detector. Simple names also match nested input fields.
            'fields' => ['email'],
            'check_mx' => true,
            'mx_cache_ttl' => 86400,
            'blacklist' => [
                // These domains will always be blocked by the EmailReputationDetector.
            ],
            'whitelist' => [
                // These domains will never be blocked by the EmailReputationDetector.
            ],
        ],
        /**
         * Block POST requests that look like automated form submissions based on their headers.
         */
        BotSignatureDetector::class => [
            'enabled' => env('THREAT_BLOCKER_BOT_SIGNATURE_DETECTOR_ENABLED', true),
            'rules' => [
                'missing_user_agent' => true,
                'known_bot_user_agents' => true,
                'missing_accept_language' => false,
                'invalid_referer' => false,
            ],
            // Patterns replace the defaults. Use array_merge() to extend them.
            'user_agent_patterns' => BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS,
        ],
        /**
         * Block requests that contain form submissions with honeypot fields filled out.
         * This detector requires spatie/laravel-honeypot package to be installed and configured.
         */
        FormHoneypotDetector::class => [
            'enabled' => env('THREAT_BLOCKER_FORM_HONEYPOT_DETECTOR_ENABLED', true),
            /**
             * Require honeypot fields on every POST request or only on the
             * configured URI patterns. The default preserves the optional
             * honeypot behavior.
             *
             * Examples: true, ['/contact', '/newsletter/*']
             */
            'strict' => false,
        ],
        /**
         * Block POST requests classified as spam or phishing by an AI model.
         * This detector requires the laravel/ai package and a provider that supports classification
         * (typesafe, openrouter, or openai from laravel/ai 1.2). Form data is sent to the provider, token, password and secret fields are excluded.
         */
        AiSpamDetector::class => [
            'enabled' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_ENABLED', false),
            // Null falls back to laravel/ai classification defaults.
            'provider' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_PROVIDER'),
            'model' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_MODEL'),
            // ['*'] sends all input. Empty fields disable this detector. Matching follows EmailReputationDetector.
            'fields' => ['*'],
            // URI patterns to evaluate, empty means all URIs. Example: ['/contact', '/newsletter/*']
            'only' => [],
            // URI pattern => extra instructions, appended to the default instructions.
            'context' => [],
            // Block when the spam + phishing probability reaches this value.
            'threshold' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_THRESHOLD', 0.8),
            // Maximum number of characters sent to the provider.
            'max_length' => 4000,
            // Seconds to wait for the provider.
            'timeout' => 5,
            // OpenRouter only: route requests to zero data retention endpoints. Models without one return an error and the request is allowed.
            'zdr' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_ZDR', false),
        ],
    ],
];
```

### Storage

Detectors keep their data (the downloaded lists and the MX lookup results) in a storage driver. The only driver
is `cache`, which uses a Laravel cache store: set `THREAT_BLOCKER_CACHE_STORE` (it falls back to `CACHE_STORE`)
and, if needed, `THREAT_BLOCKER_CACHE_PREFIX`. The lists expire after one year without updates (every update renews them).
Use a persistent store shared by all your servers (e.g. `redis` or `database`) and not `array`.

### Responder

The responder decides what a request blocked by a detector receives. The package provides:

- `BlankPageResponder` (default) answers with an empty `200` response.
- `ForbiddenResponder` aborts with a `403` response.

To customize it, implement `Keepsuit\ThreatBlocker\Contracts\ThreatResponder` and set it as the `responder`.
`$next` lets the request proceed, which is useful to only monitor threats through the event:

```php
use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Contracts\ThreatResponder;

class RedirectResponder implements ThreatResponder
{
    public function respond(Request $request, \Closure $next): mixed
    {
        return redirect()->back()->withErrors('Your request could not be processed.');
    }
}
```

### HTTP methods

Detectors run only on the methods listed in the global `methods` option (default `['POST']`),
and `*` means any method. Methods are case-insensitive names or `Keepsuit\ThreatBlocker\Enums\HttpMethod` cases. A detector can override it with its own `methods` option:

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

## Detectors

Detectors run in the order of the `detectors` option, and the first one that detects a threat blocks the request.
Detectors that download a list (`AbuseIpDetector`, `EmailReputationDetector`) refresh it with
`php artisan threat-blocker:update`, and in the background when it is older than 3 days.

### AbuseIpDetector

Blocks requests coming from the IPs of the [AbuseIPDB](https://www.abuseipdb.com) blocklist maintained by
[borestad/blocklist-abuseipdb](https://github.com/borestad/blocklist-abuseipdb).

- `source` is one of the `AbuseIpSource` urls (`Days60`, `Days30`, `Days14`, `Days7`) or a custom url with one IP per line.
- `blacklist` IPs are always blocked, `whitelist` IPs are never blocked (it wins over the blacklist and the list).
- The list contains IPv4 addresses only: an IPv6 address is blocked just when it is in `blacklist`.

It does not read the request body, so it can run on any method: set `'methods' => ['*']` to check them all.

### EmailReputationDetector

Blocks registrations using disposable or undeliverable email domains. It reads the request body.

`EmailReputationSource` provides built-in disposable-domain list URLs for the default,
DNS-validated, curated, and high-coverage sources. The `source` option also accepts any
custom URL serving one domain per line.

- `fields` are the input fields to check. An empty list disables the detector. `email` also matches nested fields
  with that name, use patterns such as `contacts.*.email` for a specific nested path.
- `blacklist` domains are always blocked, `whitelist` domains are never blocked.
- `check_mx` blocks domains that do not accept mail: no MX record and no A/AAAA fallback, or a null MX. The DNS result
  is cached for `mx_cache_ttl` seconds; when the lookup fails the request is allowed and nothing is cached.

### BotSignatureDetector

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

### FormHoneypotDetector

Blocks form submissions with a filled honeypot field (or, if `valid_from_timestamp` is enabled in the Spatie config, submitted too fast). It reads the request body and
needs [spatie/laravel-honeypot](https://github.com/spatie/laravel-honeypot) installed and its component added to
your forms; without it the check is skipped and a warning is logged.

- The check runs even if `honeypot.enabled` is `false` in the Spatie config.
- `strict` => `false` (default) checks only requests that contain the honeypot fields, `true` also blocks requests
  without them, and a list of URI patterns (e.g. `['/contact', '/newsletter/*']`) requires them only there.

### AiSpamDetector

`AiSpamDetector` classifies form data as legitimate, spam or phishing with
[`laravel/ai`](https://github.com/laravel/ai). It is disabled by default and needs
`composer require laravel/ai` plus the API key of a provider that supports classification (`typesafe`, `openrouter`, or `openai` from laravel/ai 1.2). Every evaluated request adds latency and provider cost,
so restrict it with `only` and keep it last in the detectors list.

- Form data is sent to the external provider. Files, `_method`, fields whose name contains `token`, `password` or
  `secret` (case-insensitive) and the honeypot timestamp field configured via `honeypot.valid_from_field_name`
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

Models tested on OpenRouter, ordered by lowest provider price as of 2026-11-17 (output tokens are free for all of them):

| Model                                     | Recommended | Input price / 1M tokens | Test results / limitations                                                                                                   |
|-------------------------------------------|-------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `perplexity/pplx-decider-flash-v1.3:free` | ✅           | free                    | Passes the live tests.                                                                                                       |
| `perplexity/pplx-decider-v1.3:free`       | ✅           | free                    | Passes the live tests.                                                                                                       |
| `parallel/decisions-fast`                 | ✅           | free                    | Passes the live tests.                                                                                                       |
| `~perplexity/pplx-decider-flash-latest`   | ✅           | $0.01                   | Passes the live tests and is the fastest (tested on `perplexity/pplx-decider-flash-v1.3`).                                   |
| `respan/span-02`                          | ✅           | $0.01                   | Passes the live tests.                                                                                                       |
| `~perplexity/pplx-decider-latest`         | ✅           | $0.02                   | Passes the live tests (tested on `perplexity/pplx-decider-v1.3`).                                                            |
| `~liquid/d1-latest`                       | ✅           | $0.02                   | Passes the live tests (tested on `liquid/d1.2`).                                                                             |
| `baseten/elephant-1`                      | ✅           | $0.035                  | Passes the live tests.                                                                                                       |
| `~typesafe/jev-latest`                    | ✅           | $0.042                  | Passes the live tests (tested on `typesafe/jev-1.14`).                                                                       |
| `~liquid/d1-ultra-latest`                 | ✅           | $0.042                  | Passes the live tests (tested on `liquid/d1.2-ultra`).                                                                       |
| `microsoft/microsoft-decision-1`          | ✅           | $0.042                  | Passes the live tests.                                                                                                       |
| `nace-ai/drex-max-finance`                | ✅           | $0.06                   | Passes the live tests.                                                                                                       |
| `nace-ai/drex-max`                        | ✅           | $0.06                   | Passes the live tests with the widest margins.                                                                               |
| `heygen/heygen-decision-1-turbo`          | ✅           | $0.09                   | Passes the live tests, but is the most expensive.                                                                            |
| `morph/reflex`                            | ❌           | $0.042                  | Passes the live tests, but scores close to the `threshold`.                                                                  |
| `nace-ai/drex-v1.5`                       | ❌           | $0.04                   | Passes the live tests, but scores close to the `threshold`.                                                                  |
| `jaredpalmer/kev-4b`                      | ❌           | $0.042                  | Passes the live tests, but scores close to the `threshold`.                                                                  |
| `togethercomputer/tev1-4b-experimental`   | ❌           | $0.042                  | Passes the live tests, but scores close to the `threshold`.                                                                  |
| `upstage/solar-decide-flash`              | ❌           | $0.05                   | Passes the live tests, but scores legitimate submissions up to 0.44.                                                         |
| `cloudflare/clef-flash`                   | ❌           | $0.019                  | Sometimes hits the timeout (request allowed).                                                                                |
| `nace-ai/drex-v2.0`                       | ❌           | $0.06                   | Scores close to the `threshold` and sometimes hits the timeout (request allowed).                                            |
| `baseten/joey-1`                          | ❌           | $0.01                   | Fails `generic-marketing` and `ceo-fraud-en` (scored 0.50 and 0.44, allowed).                                                |
| `upstage/solar-decide`                    | ❌           | $0.05                   | Passes the live tests, but is 5.0x slower.                                                                                   |
| `respan/span-01-lite`                     | ❌           | free                    | Returns an error: `Respan state must be a string or an object with only input (a message array) and output (a message)`.     |
| `respan/span-01-lite:free`                | ❌           | free                    | Returns an error: `Respan state must be a string or an object with only input (a message array) and output (a message)`.     |
| `respan/span-01`                          | ❌           | $0.02                   | Returns an error: `Respan state must be a string or an object with only input (a message array) and output (a message)`.     |
| `scaledown/classify-1`                    | ❌           | $0.04                   | Returns an error: `ScaleDown state must be a string, a single image_url or file part, an array of text and at most one ...`. |
| `inception/mercury-decide:free`           | ❌           | -                       | Returns an error: `No endpoints found for inception/mercury-decide:free.`                                                    |
| `inception/mercury-decide`                | ❌           | -                       | Returns an error: `No endpoints found for inception/mercury-decide.`                                                         |

The live tests cover legitimate, spam and phishing submissions in Italian and English;
validate the selected model with your own form data before production use.

## Events and logging

Detectors report a threat by throwing `ThreatDetectedException`, which exposes the `detectorId`
(e.g. `bot-signature`) and a `context` array with details about the detection. The message is prefixed with
the detector id (`[bot-signature] Known bot User-Agent detected.`).

The `ThreatDetectedEvent` event carries the `request` and the `exception`. Detectors put in the
context only derived values (category, score, domain), never request content or full email addresses.

The package does not log detections, listen to the event to log them the way your application needs (level, channel, request data):

```php
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Events\ThreatDetectedEvent;

Event::listen(function (ThreatDetectedEvent $event) {
    Log::warning($event->exception->getMessage(), [
        'method' => $event->request->method(),
        'path' => $event->request->path(),
        'ip' => $event->request->ip(),
        ...$event->exception->context,
    ]);
});
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
