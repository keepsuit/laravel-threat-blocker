<?php

namespace Keepsuit\ThreatBlocker\Commands;

use Illuminate\Console\Command;

class ThreatBlockerCommand extends Command
{
    public $signature = 'laravel-threat-blocker';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
