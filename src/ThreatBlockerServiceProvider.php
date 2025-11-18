<?php

namespace Keepsuit\ThreatBlocker;

use Keepsuit\ThreatBlocker\Commands\ThreatBlockerCommand;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ThreatBlockerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-threat-blocker')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigration('create_laravel_threat_blocker_table')
            ->hasCommand(ThreatBlockerCommand::class);
    }
}
