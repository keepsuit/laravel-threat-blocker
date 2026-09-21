<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Spatie\Honeypot\Exceptions\SpamException;
use Spatie\Honeypot\SpamProtection;

class FormHoneypotDetector implements Detector
{
    protected bool|array $strict = false;

    public function register(Application $app, array $options): void
    {
        $strict = $options['strict'] ?? false;

        $this->strict = match (true) {
            is_bool($strict) => $strict,
            is_array($strict) => array_values(
                array_filter($strict, is_string(...)),
            ),
            default => tap(
                false,
                fn () => Log::error(
                    'FormHoneypotDetector: the strict option must be a boolean or an array of URI patterns.',
                    ['type' => get_debug_type($strict)],
                ),
            ),
        };
    }

    public function check(Request $request): void
    {
        if (! $request->isMethod('POST')) {
            return;
        }

        if (! class_exists(SpamProtection::class)) {
            Log::warning(
                'FormHoneypotDetector: spatie/laravel-honeypot is not installed; honeypot checks are being skipped.',
            );

            return;
        }

        $oldEnabledValue = config('honeypot.enabled');
        $oldConfigValue = config(
            'honeypot.honeypot_fields_required_for_all_forms',
        );
        try {
            config()->set('honeypot.enabled', true);
            config()->set(
                'honeypot.honeypot_fields_required_for_all_forms',
                $this->shouldRequireFields($request),
            );

            app(SpamProtection::class)->check($request->all());
        } catch (SpamException) {
            throw new ThreatDetectedException(
                'Form honeypot detected spam submission.',
            );
        } finally {
            config()->set('honeypot.enabled', $oldEnabledValue);
            config()->set(
                'honeypot.honeypot_fields_required_for_all_forms',
                $oldConfigValue,
            );
        }
    }

    protected function shouldRequireFields(Request $request): bool
    {
        if ($this->strict === true) {
            return true;
        }

        if (! is_array($this->strict)) {
            return false;
        }

        foreach ($this->strict as $endpoint) {
            if ($request->is(ltrim($endpoint, '/'))) {
                return true;
            }
        }

        return false;
    }
}
