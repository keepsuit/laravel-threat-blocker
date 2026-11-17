<?php

namespace Keepsuit\ThreatBlocker\Contracts;

interface DnsResolver
{
    /**
     * Whether the domain can receive email, null when the DNS lookup fails.
     */
    public function acceptsMail(string $domain): ?bool;
}
