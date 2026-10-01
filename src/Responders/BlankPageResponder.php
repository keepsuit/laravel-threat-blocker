<?php

namespace Keepsuit\ThreatBlocker\Responders;

use Illuminate\Http\Request;
use Keepsuit\ThreatBlocker\Contracts\ThreatResponder;

class BlankPageResponder implements ThreatResponder
{
    public function respond(Request $request, \Closure $next): mixed
    {
        return response('');
    }
}
