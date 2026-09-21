<?php

namespace Keepsuit\ThreatBlocker\Support;

use Keepsuit\ThreatBlocker\Contracts\DnsResolver;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;

class MxRecordCache
{
    public function __construct(
        protected DnsResolver $resolver,
        protected StorageDriver $storage,
    ) {}

    public function hasMxRecord(string $domain, int $ttl): bool
    {
        $cacheKey = 'email-reputation-mx-'.sha1($domain);
        $cached = $this->storage->get($cacheKey);

        if ($cached !== null) {
            return (bool) $cached;
        }

        $hasMxRecord = $this->resolver->hasMxRecord($domain);
        $this->storage->set($cacheKey, $hasMxRecord, $ttl);

        return $hasMxRecord;
    }
}
