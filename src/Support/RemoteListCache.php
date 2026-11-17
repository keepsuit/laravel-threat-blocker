<?php

namespace Keepsuit\ThreatBlocker\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;

class RemoteListCache
{
    public const int TTL = 31536000;

    public const int REFRESH_RETRY_AFTER = 300;

    public function __construct(
        protected StorageDriver $storage,
    ) {}

    /**
     * @param  Closure(string): array  $parser
     */
    public function update(
        string $cacheKey,
        string $sourceUrl,
        string $itemsKey,
        Closure $parser,
    ): void {
        $lastUpdatedAt = CarbonImmutable::now();
        $items = $parser(Http::throw()->get($sourceUrl)->body());

        $this->storage->set($cacheKey, [
            $itemsKey => $items,
            'updated_at' => $lastUpdatedAt->timestamp,
        ], self::TTL);
    }

    /**
     * @param  Closure(string): array  $parser
     * @return array<mixed>
     */
    public function get(
        string $cacheKey,
        string $sourceUrl,
        string $itemsKey,
        string $name,
        Closure $parser,
    ): array {
        [$items, $lastUpdatedAt] = $this->read($cacheKey, $itemsKey);

        if ($items === null && $this->claimRefresh($cacheKey)) {
            Log::warning("{$name}: source data not found in storage, fetching from source...");
            rescue(fn () => $this->update($cacheKey, $sourceUrl, $itemsKey, $parser));

            [$items, $lastUpdatedAt] = $this->read($cacheKey, $itemsKey);
        }

        if (
            ($lastUpdatedAt === null || $lastUpdatedAt->isBefore(Carbon::now()->subDays(3)))
            && $this->claimRefresh($cacheKey)
        ) {
            defer(fn () => $this->update($cacheKey, $sourceUrl, $itemsKey, $parser));
        }

        return $items ?? [];
    }

    /**
     * @return array{0: array<mixed>|null, 1: Carbon|null}
     */
    protected function read(string $cacheKey, string $itemsKey): array
    {
        $cacheData = $this->storage->get($cacheKey);

        if (! is_array($cacheData)) {
            return [null, null];
        }

        if (! isset($cacheData['updated_at'])) {
            return [$cacheData, null];
        }

        return [$cacheData[$itemsKey] ?? [], Carbon::createFromTimestamp($cacheData['updated_at'])];
    }

    /**
     * Lets a single request refresh the list, the others keep using the cached one.
     * A failed refresh is retried after REFRESH_RETRY_AFTER seconds.
     */
    protected function claimRefresh(string $cacheKey): bool
    {
        $flagKey = $cacheKey.'-refreshing';

        // ponytail: get + set is not atomic, a few concurrent requests can still refresh together; use a cache lock if that matters.
        if ($this->storage->get($flagKey) !== null) {
            return false;
        }

        $this->storage->set($flagKey, true, self::REFRESH_RETRY_AFTER);

        return true;
    }
}
