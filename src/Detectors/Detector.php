<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;

interface Detector
{
    public function register(Application $app, array $options): void;
}
