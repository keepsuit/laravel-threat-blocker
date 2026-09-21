<?php

namespace Keepsuit\ThreatBlocker\Contracts;

interface DnsResolver
{
    public function hasMxRecord(string $domain): bool;
}
