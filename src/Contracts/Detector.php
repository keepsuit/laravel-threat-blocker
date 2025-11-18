<?php

namespace Keepsuit\ThreatBlocker\Contracts;

use Illuminate\Foundation\Application;

interface Detector
{
    public function register(Application $app, array $options): void;
}
