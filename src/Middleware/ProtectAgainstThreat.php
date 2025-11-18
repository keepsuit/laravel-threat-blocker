<?php

namespace Keepsuit\ThreatBlocker\Middleware;

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Events\ThreatDetectedEvent;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;

class ProtectAgainstThreat
{
    public function __construct(
        protected ThreatBlocker $threatBlocker
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

                abort(403);
            }
        }

        return $next($request);
    }
}
