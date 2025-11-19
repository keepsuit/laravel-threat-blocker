<?php

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

    /*
     * The responder class that will be used to respond to detected threats.
     * You can create your own responder by implementing the Keepsuit\ThreatBlocker\Contracts\ThreatResponder interface.
     */
    'responder' => \Keepsuit\ThreatBlocker\Reponders\BlankPageResponder::class,

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
         * Block requests that contain form submissions with honeypot fields filled out.
         * This detector requires spatie/laravel-honeypot package to be installed and configured.
         */
        \Keepsuit\ThreatBlocker\Detectors\FormHoneypotDetector::class => [
            'enabled' => env('THREAT_BLOCKER_FORM_HONEYPOT_DETECTOR_ENABLED', true),
        ],
    ],
];
