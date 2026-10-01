<?php

namespace Keepsuit\ThreatBlocker\Exceptions;

class ThreatDetectedException extends \Exception
{
    /**
     * @param  array<string, mixed>  $context  Details about the detection, exposed to listeners:
     *                                         use only derived values (category, score, domain), never request content or full email addresses.
     */
    public function __construct(
        public readonly string $detectorId,
        string $message,
        public readonly array $context = [],
    ) {
        parent::__construct("[{$detectorId}] {$message}");
    }
}
