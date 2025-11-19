<?php

namespace Keepsuit\ThreatBlocker;

use Illuminate\Foundation\Application;
use Keepsuit\ThreatBlocker\Commands\UpdateAbuseIpCommand;
use Keepsuit\ThreatBlocker\Contracts\Detector;
use Keepsuit\ThreatBlocker\Contracts\StorageDriver;
use Keepsuit\ThreatBlocker\Contracts\ThreatResponder;
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
        $this->app->bind(ThreatResponder::class, config('threat-blocker.responder'));

        $this->app->bind(StorageDriver::class, function (Application $app) {
            $driver = $app['config']->get('threat-blocker.storage_driver');

            return match ($driver) {
                'cache' => new Storage\CacheStorageDriver($app['config']->get('threat-blocker.storage.cache')),
                default => throw new \InvalidArgumentException('Invalid storage driver specified for Threat Blocker: '.$driver),
            };
        });

        $this->app->scoped(ThreatBlocker::class, function (Application $app) {
            $threatBlocker = new ThreatBlocker(
                config('threat-blocker.enabled', true)
            );

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
