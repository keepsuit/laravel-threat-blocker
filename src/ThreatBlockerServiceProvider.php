<?php

namespace Keepsuit\ThreatBlocker;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Keepsuit\ThreatBlocker\Commands\ThreatBlockerCommand;

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
