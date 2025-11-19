<?php

namespace Keepsuit\ThreatBlocker\Middleware;

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Contracts\ThreatResponder;
use Keepsuit\ThreatBlocker\Events\ThreatDetectedEvent;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;

class ProtectAgainstThreats
{
    public function __construct(
        protected ThreatBlocker $threatBlocker,
        protected ThreatResponder $responder
    ) {}

    public function handle(Request $request, \Closure $next): mixed
    {
        if (! $this->threatBlocker->enabled()) {
            return $next($request);
        }

        foreach ($this->threatBlocker->allDetectors() as $detector) {
            try {
                $detector->check($request);
            } catch (ThreatDetectedException $exception) {
                event(new ThreatDetectedEvent(
                    request: $request,
                    detectorId: $this->threatBlocker->detectorId($detector),
                    exception: $exception
                ));

                return $this->responder->respond($request, $next);
            }
        }

        return $next($request);
    }
}
