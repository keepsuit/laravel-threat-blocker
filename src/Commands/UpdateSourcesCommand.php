<?php

namespace Keepsuit\ThreatBlocker\Commands;

use Illuminate\Console\Command;
use Keepsuit\ThreatBlocker\Contracts\SourceUpdatable;
use Keepsuit\ThreatBlocker\ThreatBlocker;
use Throwable;

class UpdateSourcesCommand extends Command
{
    public $signature = 'threat-blocker:update';

    public $description = 'Update detectors sources';

    public function handle(ThreatBlocker $threatBlocker): int
    {
        $this->outputComponents()->info('Updating threat blocker detectors sources...');

        $result = self::SUCCESS;

        foreach ($threatBlocker->allDetectors() as $detector) {
            if (! $detector instanceof SourceUpdatable) {
                continue;
            }

            $this->outputComponents()->task($detector->id(), function () use ($detector, &$result) {
                try {
                    $detector->updateSource();

                    return true;
                } catch (Throwable $e) {
                    report($e);
                    $result = self::FAILURE;

                    return false;
                }
            });
        }

        return $result;
    }
}
