<?php

namespace Keepsuit\ThreatBlocker;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ThreatBlockerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-threat-blocker')
            ->hasConfigFile();
    }
}
