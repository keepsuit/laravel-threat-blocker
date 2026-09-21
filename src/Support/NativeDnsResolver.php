<?php

namespace Keepsuit\ThreatBlocker\Support;

use Keepsuit\ThreatBlocker\Contracts\DnsResolver;

class NativeDnsResolver implements DnsResolver
{
    public function hasMxRecord(string $domain): bool
    {
        return checkdnsrr($domain, 'MX');
    }
}
