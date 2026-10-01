<?php

namespace Keepsuit\ThreatBlocker;

use Illuminate\Support\Arr;
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
        public bool $logging = false,
    ) {}

    public function enabled(): bool
    {
        return $this->enabled;
    }

    public function logging(): bool
    {
        return $this->logging;
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
        foreach ($this->detectors as $detector) {
            if ($detector instanceof $class) {
                return $detector;
            }
        }

        return null;
    }

    public function getDetectorById(string $id): ?Detector
    {
        return Arr::first($this->detectors, fn (Detector $detector) => $this->detectorId($detector) === $id);
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
        return self::idFor($detector::class);
    }

    /**
     * @param  class-string<Detector>  $class
     */
    public static function idFor(string $class): string
    {
        return Str::of(class_basename($class))
            ->chopEnd('Detector')
            ->kebab()
            ->toString();
    }
}
