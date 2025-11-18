<?php

namespace Keepsuit\ThreatBlocker\Commands;

use Illuminate\Console\Command;
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

            $this->outputComponents()->task($threatBlocker->detectorId($detector), fn () => $detector->updateSource());
        }

        return self::SUCCESS;
    }
}
