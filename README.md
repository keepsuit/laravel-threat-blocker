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
    ],
];
```

`EmailReputationSource` provides built-in disposable-domain list URLs for the default,
DNS-validated, curated, and high-coverage sources. The `source` option also accepts any
custom URL serving one domain per line.

`BotSignatureDetector` checks only `POST` requests. Each configured rule is independent:

- `missing_user_agent` blocks missing or blank User-Agent headers.
- `known_bot_user_agents` matches the configurable case-insensitive PCRE patterns.
- `missing_accept_language` blocks missing or blank Accept-Language headers.
- `invalid_referer` blocks missing, malformed, or cross-host Referer headers.

The default User-Agent patterns are conservative and available through
`BotSignatureDetector::DEFAULT_USER_AGENT_PATTERNS`. Supplying `user_agent_patterns`
replaces them; extend them with `array_merge()` when needed. Crawler and link-preview
identities such as Googlebot, bingbot, Slackbot, and Discordbot are intentionally not
included in the defaults.

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

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Credits

- [Fabio Capucci](https://github.com/keepsuit)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
