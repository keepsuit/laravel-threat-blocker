<?php

use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\BotSignatureDetector;
use Keepsuit\ThreatBlocker\Detectors\EmailReputationDetector;
use Keepsuit\ThreatBlocker\Detectors\FormHoneypotDetector;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
use Keepsuit\ThreatBlocker\Enums\EmailReputationSource;
use Keepsuit\ThreatBlocker\Reponders\BlankPageResponder;

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
            'store' => env('THREAT_BLOCKER_CACHE_STORE', env('CACHE_STORE', env('CACHE_DRIVER', 'file'))),
            'prefix' => env('THREAT_BLOCKER_CACHE_PREFIX', 'threat_blocker'),
        ],
    ],

    /*
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
    ],
];
