<?php

namespace Keepsuit\ThreatBlocker\Events;

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;

class ThreatDetectedEvent
{
    public function __construct(
        public Request $request,
        public string $detectorId,
        public ThreatDetectedException $exception
    ) {}
}
