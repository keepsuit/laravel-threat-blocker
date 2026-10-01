<?php

namespace Keepsuit\ThreatBlocker\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Http;
use Keepsuit\ThreatBlocker\ThreatBlockerServiceProvider;
use Laravel\Ai\AiServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Spatie\Honeypot\HoneypotServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('app.key', 'base64:2RKJuyp3j0d6o5rFCjoTiB4J4+G0SNRAuz57LipJiM8=');

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Keepsuit\\ThreatBlocker\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );

        Http::preventStrayRequests();
    }

    protected function getPackageProviders($app): array
    {
        return [
            AiServiceProvider::class,
            HoneypotServiceProvider::class,
            ThreatBlockerServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('database.default', 'testing');
        config()->set('threat-blocker.storage.cache.store', 'array');
    }
}
