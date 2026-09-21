<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
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
            is_array($strict) => array_values(array_filter($strict, is_string(...))),
            default => false,
        };
    }

    public function check(Request $request): void
    {
        if (! $request->isMethod('POST')) {
            return;
        }

        if (! class_exists(SpamProtection::class)) {
            return;
        }

        $oldConfigValue = config('honeypot.honeypot_fields_required_for_all_forms');
        try {
            config()->set(
                'honeypot.honeypot_fields_required_for_all_forms',
                $this->shouldRequireFields($request),
            );

            app(SpamProtection::class)->check($request->all());
        } catch (SpamException) {
            throw new ThreatDetectedException('Form honeypot detected spam submission.');
        } finally {
            config()->set('honeypot.honeypot_fields_required_for_all_forms', $oldConfigValue);
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
