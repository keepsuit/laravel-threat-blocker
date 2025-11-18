<?php

namespace Keepsuit\ThreatBlocker;

use Illuminate\Foundation\Application;
use Keepsuit\ThreatBlocker\Commands\UpdateAbuseIpCommand;
use Keepsuit\ThreatBlocker\Detectors\Detector;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ThreatBlockerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-threat-blocker')
            ->hasConfigFile()
            ->hasCommands(
                UpdateAbuseIpCommand::class,
            );
    }

    public function packageBooted(): void
    {
        $this->registerBindings();
    }

    protected function registerBindings(): void
    {
        $this->app->scoped(ThreatBlocker::class, function (Application $app) {
            $threatBlocker = new ThreatBlocker;

            foreach (config('threat-blocker.detectors') as $key => $options) {
                if (is_string($key) && $options === false) {
                    continue;
                }

                if (is_array($options) && ! ($options['enabled'] ?? true)) {
                    continue;
                }

                $detector = $app->make(is_string($key) ? $key : $options);

                if (! $detector instanceof Detector) {
                    continue;
                }

                $detector->register($app, is_array($options) ? $options : []);

                $threatBlocker->addDetector($detector);
            }

            return $threatBlocker;
        });
    }
}
