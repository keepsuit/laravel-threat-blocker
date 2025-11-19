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
    public function register(Application $app, array $options): void {}

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
            config()->set('honeypot.honeypot_fields_required_for_all_forms', false);

            app(SpamProtection::class)->check($request->all());
        } catch (SpamException) {
            throw new ThreatDetectedException('Form honeypot detected spam submission.');
        } finally {
            config()->set('honeypot.honeypot_fields_required_for_all_forms', $oldConfigValue);
        }
    }
}
