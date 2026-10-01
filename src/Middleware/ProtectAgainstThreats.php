<?php

namespace Keepsuit\ThreatBlocker\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
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
                if ($this->threatBlocker->logging()) {
                    Log::warning($exception->getMessage(), [
                        'method' => $request->method(),
                        'path' => $request->path(),
                        'ip' => $request->ip(),
                        ...$exception->context,
                    ]);
                }

                event(new ThreatDetectedEvent(request: $request, exception: $exception));

                return $this->responder->respond($request, $next);
            }
        }

        return $next($request);
    }
}
