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
    /**
     * @var string[]
     */
    protected array $requiredPaths = [];

    public function register(Application $app, array $options): void
    {
        $this->requiredPaths = $options['required_paths'] ?? [];
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
            // Submissions without the honeypot fields are only spam on the forms that render
            // them: requiring them everywhere would reject plain POST endpoints and APIs.
            config()->set('honeypot.honeypot_fields_required_for_all_forms', $request->is(...$this->requiredPaths));

            app(SpamProtection::class)->check($request->all());
        } catch (SpamException) {
            throw new ThreatDetectedException('Form honeypot detected spam submission.');
        } finally {
            config()->set('honeypot.honeypot_fields_required_for_all_forms', $oldConfigValue);
        }
    }
}
