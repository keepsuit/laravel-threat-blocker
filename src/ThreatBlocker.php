<?php

namespace Keepsuit\ThreatBlocker;

use Keepsuit\ThreatBlocker\Detectors\Detector;

final class ThreatBlocker
{
    /**
     * @var Detector[]
     */
    protected array $detectors = [];

    public function addDetector(Detector $detector): ThreatBlocker
    {
        $this->detectors[] = $detector;

        return $this;
    }

    /**
     * @template TClass of Detector
     *
     * @param  class-string<TClass>  $class
     * @return TClass|null
     */
    public function getDetector(string $class): ?Detector
    {
        return array_find($this->detectors, fn (Detector $detector) => $detector instanceof $class);
    }
}
