<?php

namespace Keepsuit\ThreatBlocker\Support;

use Illuminate\Support\Str;

class InputFields
{
    /**
     * Simple names match the terminal segment of a dotted input key, patterns containing a dot match the full key.
     *
     * @param  string[]  $fields
     */
    public static function matches(array $fields, string $key): bool
    {
        foreach ($fields as $field) {
            $subject = str_contains($field, '.')
                ? $key
                : Str::afterLast($key, '.');

            if (Str::is($field, $subject)) {
                return true;
            }
        }

        return false;
    }
}
