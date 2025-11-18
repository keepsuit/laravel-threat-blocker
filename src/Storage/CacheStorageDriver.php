<?php

namespace Keepsuit\ThreatBlocker\Storage;

use DateTimeInterface;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Illuminate\Support\Stringable;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;

class CacheStorageDriver implements StorageDriver
{
    protected Repository $store;

    protected string $prefix;

    public function __construct(array $options)
    {
        $this->store = Cache::store($options['store'] ?? null);
        $this->prefix = Str::of($options['prefix'] ?? '')
            ->trim('.')
            ->whenNotEmpty(fn (Stringable $str) => $str->append('.'))
            ->toString();
    }

    public function set(string $key, mixed $value, int|DateTimeInterface|null $ttl = null): void
    {
        if ($ttl === null) {
            $this->store->forever($this->prefix.$key, $value);
        } else {
            $this->store->put($this->prefix.$key, $value, $ttl);
        }
    }

    public function get(string $key): mixed
    {
        return $this->store->get($this->prefix.$key);
    }
}
