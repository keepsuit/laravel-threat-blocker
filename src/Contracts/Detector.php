<?php

namespace Keepsuit\ThreatBlocker\Contracts;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;

interface Detector
{
    public function register(Application $app, array $options): void;

    /**
     * @throws ThreatDetectedException
     */
    public function check(Request $request): void;
}
