<?php

namespace Keepsuit\ThreatBlocker\Support;

use Illuminate\Http\Request;

class RequestMethods
{
    /**
     * @var string[]
     */
    public const array DEFAULT = ['POST'];

    /**
     * Methods that carry a request body, the only ones supported by detectors that inspect it.
     *
     * @var string[]
     */
    public const array BODY = ['POST', 'PUT', 'PATCH'];

    /**
     * Resolves the `methods` option, `*` means any method.
     *
     * @param  array<string, mixed>  $options
     * @return string[]
     */
    public static function resolve(array $options, bool $bodyOnly = false): array
    {
        $methods = $options['methods'] ?? self::DEFAULT;
        $methods = is_array($methods)
            ? array_values(array_unique(array_map(strtoupper(...), array_filter($methods, is_string(...)))))
            : [];

        if (! $bodyOnly) {
            return $methods;
        }

        return in_array('*', $methods, true)
            ? self::BODY
            : array_values(array_intersect($methods, self::BODY));
    }

    /**
     * @param  string[]  $methods
     */
    public static function matches(array $methods, Request $request): bool
    {
        return in_array('*', $methods, true) || in_array($request->method(), $methods, true);
    }
}
