<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;

class BotSignatureDetector implements Detector
{
    /**
     * @var string[]
     */
    public const array DEFAULT_USER_AGENT_PATTERNS = [
        '/curl/i',
        '/python-requests/i',
        '/Go-http-client/i',
        '/libwww/i',
        '/Scrapy/i',
        '/wget/i',
        '/HTTPie/i',
        '/okhttp/i',
    ];

    /**
     * @var array<string,bool>
     */
    protected array $rules = [];

    /**
     * @var string[]
     */
    protected array $userAgentPatterns = self::DEFAULT_USER_AGENT_PATTERNS;

    public function register(Application $app, array $options): void
    {
        $rules = is_array($options['rules'] ?? null)
            ? $options['rules']
            : [];

        $this->rules = [
            'missing_user_agent' => ($rules['missing_user_agent'] ?? true) === true,
            'known_bot_user_agents' => ($rules['known_bot_user_agents'] ?? true) === true,
            'missing_accept_language' => ($rules['missing_accept_language'] ?? false) === true,
            'invalid_referer' => ($rules['invalid_referer'] ?? false) === true,
        ];

        $patterns = $options['user_agent_patterns'] ?? self::DEFAULT_USER_AGENT_PATTERNS;
        $patterns = is_array($patterns)
            ? array_values(array_filter($patterns, is_string(...)))
            : self::DEFAULT_USER_AGENT_PATTERNS;

        $this->userAgentPatterns = [];

        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, '') === false) {
                Log::warning(
                    'BotSignatureDetector: invalid User-Agent pattern skipped.',
                    ['pattern' => $pattern],
                );

                continue;
            }

            $this->userAgentPatterns[] = $pattern;
        }
    }

    public function check(Request $request): void
    {
        if (! $request->isMethod('POST')) {
            return;
        }

        $userAgent = trim((string) $request->headers->get('User-Agent', ''));

        if ($this->rules['missing_user_agent'] && $userAgent === '') {
            throw new ThreatDetectedException('Missing User-Agent detected.');
        }

        if ($this->rules['known_bot_user_agents']) {
            foreach ($this->userAgentPatterns as $pattern) {
                if (preg_match($pattern, $userAgent) === 1) {
                    throw new ThreatDetectedException('Known bot User-Agent detected.');
                }
            }
        }

        if (
            $this->rules['missing_accept_language']
            && trim((string) $request->headers->get('Accept-Language', '')) === ''
        ) {
            throw new ThreatDetectedException('Missing Accept-Language detected.');
        }

        if ($this->rules['invalid_referer']) {
            $referer = trim((string) $request->headers->get('Referer', ''));
            $refererHost = $referer === '' ? null : parse_url($referer, PHP_URL_HOST);

            if (
                ! is_string($refererHost)
                || strcasecmp($refererHost, $request->getHost()) !== 0
            ) {
                throw new ThreatDetectedException('Invalid Referer detected.');
            }
        }
    }
}
