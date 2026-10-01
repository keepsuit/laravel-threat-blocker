<?php

namespace Keepsuit\ThreatBlocker\Enums;

use Illuminate\Http\Request;
use Illuminate\Support\Arr;

enum HttpMethod: string
{
    case Get = 'GET';
    case Head = 'HEAD';
    case Post = 'POST';
    case Put = 'PUT';
    case Patch = 'PATCH';
    case Delete = 'DELETE';
    case Options = 'OPTIONS';

    /**
     * @var HttpMethod[]
     */
    public const array DEFAULT = [self::Post];

    /**
     * Methods that carry a request body, the only ones supported by detectors that inspect it.
     *
     * @var HttpMethod[]
     */
    public const array BODY = [self::Post, self::Put, self::Patch];

    /**
     * Resolves the `methods` option: case-insensitive names or enum cases, `*` means any method.
     *
     * @param  array<string, mixed>  $options
     * @return HttpMethod[]
     */
    public static function fromOptions(array $options, bool $bodyOnly = false): array
    {
        $methods = [];

        foreach (Arr::wrap($options['methods'] ?? self::DEFAULT) as $method) {
            $resolved = match (true) {
                $method instanceof self => [$method],
                $method === '*' => self::cases(),
                is_string($method) => array_filter([self::tryFrom(strtoupper($method))]),
                default => [],
            };

            foreach ($resolved as $case) {
                if (! in_array($case, $methods, true) && (! $bodyOnly || in_array($case, self::BODY, true))) {
                    $methods[] = $case;
                }
            }
        }

        return $methods;
    }

    /**
     * @param  HttpMethod[]  $methods
     */
    public static function matches(array $methods, Request $request): bool
    {
        return in_array(self::tryFrom($request->method()), $methods, true);
    }
}
