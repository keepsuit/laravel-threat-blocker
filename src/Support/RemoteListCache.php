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
        ]);
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
        $cacheData = $this->storage->get($cacheKey);
        $lastUpdatedAt = null;
        $items = null;

        if (is_array($cacheData)) {
            if (isset($cacheData['updated_at'])) {
                $lastUpdatedAt = Carbon::createFromTimestamp($cacheData['updated_at']);
                $items = $cacheData[$itemsKey] ?? [];
            } else {
                $items = $cacheData;
            }
        }

        if ($items === null) {
            Log::warning("{$name}: source data not found in storage, fetching from source...");
            rescue(fn () => $this->update($cacheKey, $sourceUrl, $itemsKey, $parser));

            $cacheData = $this->storage->get($cacheKey);
            if (is_array($cacheData)) {
                $lastUpdatedAt = isset($cacheData['updated_at'])
                    ? Carbon::createFromTimestamp($cacheData['updated_at'])
                    : null;
                $items = isset($cacheData['updated_at'])
                    ? ($cacheData[$itemsKey] ?? [])
                    : $cacheData;
            }
        }

        if ($lastUpdatedAt === null || $lastUpdatedAt->isBefore(Carbon::now()->subDays(3))) {
            defer(fn () => $this->update($cacheKey, $sourceUrl, $itemsKey, $parser));
        }

        return is_array($items) ? $items : [];
    }
}
