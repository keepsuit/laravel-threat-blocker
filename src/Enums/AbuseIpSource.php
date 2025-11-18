<?php

namespace Keepsuit\ThreatBlocker\Enums;

enum AbuseIpSource
{
    case Days30;
    case Days14;
    case Days7;

    public function url(): string
    {
        return match ($this) {
            self::Days30 => 'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4',
            self::Days14 => 'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-14d.ipv4',
            self::Days7 => 'https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-7d.ipv4',
        };
    }
}
