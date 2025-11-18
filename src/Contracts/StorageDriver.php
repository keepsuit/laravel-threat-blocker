<?php

namespace Keepsuit\ThreatBlocker\Contracts;

use DateTimeInterface;

interface StorageDriver
{
    public function set(string $key, mixed $value, int|DateTimeInterface|null $ttl = null): void;

    public function get(string $key): mixed;
}
