<?php

use Keepsuit\ThreatBlocker\Detectors\AbuseIpDetector;
use Keepsuit\ThreatBlocker\Detectors\FormHoneypotDetector;
use Keepsuit\ThreatBlocker\Detectors\RepeatedPayloadDetector;
use Keepsuit\ThreatBlocker\Enums\AbuseIpSource;
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
         * Block form submissions repeating an identical payload, as a bot filling a static
         * template does, even when it renders the form and rotates its source address.
         * It only looks at the paths listed below: with none, the detector does nothing.
         */
        RepeatedPayloadDetector::class => [
            'enabled' => env('THREAT_BLOCKER_REPEATED_PAYLOAD_DETECTOR_ENABLED', true),
            // Seconds each count covers, and how many identical payloads are tolerated within it.
            'window' => 3600,
            'threshold' => 10,
            /**
             * Path pattern => fields to fingerprint. Choose the fields a real visitor fills
             * with their own data (a name, a phone number), never the one the bot varies to
             * make each submission unique, which is usually the email address.
             */
            'paths' => [
                // 'register' => ['first_name', 'last_name', 'phone'],
            ],
        ],
    ],
];
