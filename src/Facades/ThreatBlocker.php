<?php

namespace Keepsuit\ThreatBlocker\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Keepsuit\ThreatBlocker\ThreatBlocker
 */
class ThreatBlocker extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Keepsuit\ThreatBlocker\ThreatBlocker::class;
    }
}
