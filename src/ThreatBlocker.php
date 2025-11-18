<?php

namespace Keepsuit\ThreatBlocker;

use Illuminate\Support\Str;
use Keepsuit\ThreatBlocker\Contracts\Detector;

final class ThreatBlocker
{
    /**
     * @var Detector[]
     */
    protected array $detectors = [];

    public function __construct(
        public bool $enabled = true,
    ) {}

    public function enabled(): bool
    {
        return $this->enabled;
    }

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

    public function getDetectorById(string $id): ?Detector
    {
        return array_find($this->detectors, fn (Detector $detector) => $this->detectorId($detector) === $id);
    }

    /**
     * @return Detector[]
     */
    public function allDetectors(): array
    {
        return $this->detectors;
    }

    public function detectorId(Detector $detector): string
    {
        return Str::of(class_basename($detector))
            ->rtrim('Detector')
            ->slug()
            ->toString();
    }
}
