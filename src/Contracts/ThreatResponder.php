<?php

namespace Keepsuit\ThreatBlocker\Contracts;

use Illuminate\Http\Request;

interface ThreatResponder
{
    public function respond(Request $request, \Closure $next): mixed;
}
