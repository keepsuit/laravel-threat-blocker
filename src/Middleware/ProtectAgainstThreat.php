<?php

namespace Keepsuit\ThreatBlocker\Middleware;

use Illuminate\Http\Request;

class ProtectAgainstThreat
{
    public function handle(Request $request, \Closure $next): mixed
    {
        return $next($request);
    }
}
