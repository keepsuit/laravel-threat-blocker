<?php

namespace Keepsuit\ThreatBlocker\Detectors;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\DnsResolver;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Enums\EmailReputationSource;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\Support\RemoteListCache;

class EmailReputationDetector implements Detector, SourceUpdatable
{
    public const string LIST_CACHE_KEY = 'email-reputation-domains';

    /**
     * @var string[]
     */
    protected array $fields = ['email'];

    protected string $sourceUrl;

    protected bool $checkMx = true;

    protected int $mxCacheTtl = 86400;

    /**
     * @var string[]
     */
    protected array $blacklistDomains = [];

    /**
     * @var string[]
     */
    protected array $whitelistDomains = [];

    /**
     * @var string[]|null
     */
    protected ?array $disposableDomains = null;

    public function __construct(
        protected RemoteListCache $remoteListCache,
        protected StorageDriver $storage,
        protected DnsResolver $dnsResolver,
    ) {}

    public function register(Application $app, array $options): void
    {
        $this->sourceUrl = is_string($options['source'] ?? null)
            ? $options['source']
            : EmailReputationSource::DisposableEmailDomains->url();
        $fields = $options['fields'] ?? ['email'];
        $this->fields = is_array($fields)
            ? array_values(array_filter($fields, is_string(...)))
            : [];
        $this->checkMx = ($options['check_mx'] ?? true) === true;
        $mxCacheTtl = $options['mx_cache_ttl'] ?? null;
        $this->mxCacheTtl = is_int($mxCacheTtl)
            ? max(0, $mxCacheTtl)
            : 86400;
        $this->blacklistDomains = $this->normalizeDomains($options['blacklist'] ?? []);
        $this->whitelistDomains = $this->normalizeDomains($options['whitelist'] ?? []);
    }

    public function updateSource(): void
    {
        $this->remoteListCache->update(
            static::LIST_CACHE_KEY,
            $this->sourceUrl,
            'domains',
            $this->parseDisposableDomains(...),
        );
    }

    public function check(Request $request): void
    {
        foreach ($this->emailCandidates($request) as $email) {
            $domain = $this->emailDomain($email);

            if ($domain === null || in_array($domain, $this->whitelistDomains, true)) {
                continue;
            }

            if (in_array($domain, $this->blacklistDomains, true)) {
                throw new ThreatDetectedException('Blacklisted email domain detected.');
            }

            if (in_array($domain, $this->getDisposableDomains(), true)) {
                throw new ThreatDetectedException('Disposable email domain detected.');
            }

            if ($this->checkMx && ! $this->hasMxRecord($domain)) {
                throw new ThreatDetectedException('Email domain has no MX record.');
            }
        }
    }

    /**
     * @return string[]
     */
    protected function emailCandidates(Request $request): array
    {
        if ($this->fields === []) {
            return [];
        }

        $candidates = [];

        foreach (Arr::dot($request->all()) as $key => $value) {
            if (! is_string($value) || ! $this->matchesField($key)) {
                continue;
            }

            if (filter_var($value, FILTER_VALIDATE_EMAIL) !== false) {
                $candidates[] = $value;
            }
        }

        return array_values(array_unique($candidates));
    }

    protected function matchesField(string $key): bool
    {
        foreach ($this->fields as $field) {
            $subject = str_contains($field, '.')
                ? $key
                : Str::afterLast($key, '.');

            if (Str::is($field, $subject)) {
                return true;
            }
        }

        return false;
    }

    protected function emailDomain(string $email): ?string
    {
        $atPosition = strrpos($email, '@');

        if ($atPosition === false) {
            return null;
        }

        return rtrim(strtolower(substr($email, $atPosition + 1)), '.');
    }

    protected function hasMxRecord(string $domain): bool
    {
        $cacheKey = 'email-reputation-mx-'.sha1($domain);
        $cached = $this->storage->get($cacheKey);

        if ($cached !== null) {
            return (bool) $cached;
        }

        $hasMxRecord = $this->dnsResolver->hasMxRecord($domain);
        $this->storage->set($cacheKey, $hasMxRecord, $this->mxCacheTtl);

        return $hasMxRecord;
    }

    /**
     * @return string[]
     */
    protected function getDisposableDomains(): array
    {
        if ($this->disposableDomains === null) {
            $this->disposableDomains = $this->remoteListCache->get(
                static::LIST_CACHE_KEY,
                $this->sourceUrl,
                'domains',
                static::class,
                $this->parseDisposableDomains(...),
            );
        }

        return $this->disposableDomains;
    }

    /**
     * @return string[]
     */
    protected function parseDisposableDomains(string $body): array
    {
        $domains = [];

        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $domain = strtolower(trim($line));

            if ($domain === '' || str_starts_with($domain, '#')) {
                continue;
            }

            if (filter_var('user@'.$domain, FILTER_VALIDATE_EMAIL) !== false) {
                $domains[] = $domain;
            }
        }

        return array_values(array_unique($domains));
    }

    /**
     * @return string[]
     */
    protected function normalizeDomains(mixed $domains): array
    {
        if (! is_array($domains)) {
            return [];
        }

        return array_values(array_unique(array_map(
            fn (string $domain): string => rtrim(strtolower(trim($domain)), '.'),
            array_filter($domains, is_string(...)),
        )));
    }
}
