<?php

namespace Keepsuit\ThreatBlocker\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\ThreatBlocker;

class UpdateAbuseIpCommand extends Command
{
    public $signature = 'threat-blocker:update';

    public $description = 'Update detectors sources';

    public function handle(ThreatBlocker $threatBlocker): int
    {
        $this->outputComponents()->info('Updating threat blocker detectors sources...');

        foreach ($threatBlocker->allDetectors() as $detector) {
            if (! $detector instanceof SourceUpdatable) {
                continue;
            }

            $this->outputComponents()->task($this->detectorName($detector), fn () => $detector->updateSource());
        }

        return self::SUCCESS;
    }

    protected function detectorName(Detector $detector): string
    {
        return Str::of(class_basename($detector))
            ->rtrim('Detector')
            ->slug()
            ->toString();
    }
}
