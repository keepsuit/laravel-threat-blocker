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

    protected bool $missingUserAgent = true;

    protected bool $knownBotUserAgents = true;

    protected bool $missingAcceptLanguage = false;

    protected bool $invalidReferer = false;

    /**
     * @var string[]
     */
    protected array $userAgentPatterns = self::DEFAULT_USER_AGENT_PATTERNS;

    public function register(Application $app, array $options): void
    {
        $rules = is_array($options['rules'] ?? null)
            ? $options['rules']
            : [];

        $this->missingUserAgent = ($rules['missing_user_agent'] ?? true) === true;
        $this->knownBotUserAgents = ($rules['known_bot_user_agents'] ?? true) === true;
        $this->missingAcceptLanguage = ($rules['missing_accept_language'] ?? false) === true;
        $this->invalidReferer = ($rules['invalid_referer'] ?? false) === true;

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

        if ($this->missingUserAgent && $userAgent === '') {
            throw new ThreatDetectedException('Missing User-Agent detected.');
        }

        if ($this->knownBotUserAgents) {
            foreach ($this->userAgentPatterns as $pattern) {
                if (preg_match($pattern, $userAgent) === 1) {
                    throw new ThreatDetectedException('Known bot User-Agent detected.');
                }
            }
        }

        if (
            $this->missingAcceptLanguage
            && trim((string) $request->headers->get('Accept-Language', '')) === ''
        ) {
            throw new ThreatDetectedException('Missing Accept-Language detected.');
        }

        if ($this->invalidReferer) {
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
