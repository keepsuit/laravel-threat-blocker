<?php

namespace Keepsuit\ThreatBlocker\Support;

use Keepsuit\ThreatBlocker\Contracts\DnsResolver;

class NativeDnsResolver implements DnsResolver
{
    public function acceptsMail(string $domain): ?bool
    {
        // Trailing dot: absolute lookup, the resolver search domains are not appended.
        $fqdn = rtrim($domain, '.').'.';

        $mx = @dns_get_record($fqdn, DNS_MX);

        if ($mx === false) {
            return null;
        }

        if ($mx !== []) {
            // A null MX (RFC 7505) has an empty target: the domain accepts no mail.
            return collect($mx)->contains(fn (array $record) => ($record['target'] ?? '') !== '');
        }

        // Without MX records mail is delivered to the A/AAAA host (RFC 5321 implicit MX).
        $hosts = @dns_get_record($fqdn, DNS_A | DNS_AAAA);

        return $hosts === false ? null : $hosts !== [];
    }
}
