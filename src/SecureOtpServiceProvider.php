<?php

declare(strict_types=1);

namespace Biponix\SecureOtp;

use Biponix\SecureOtp\Commands\CleanOtpsCommand;
use Biponix\SecureOtp\Services\SecureOtpService;
use Illuminate\Contracts\Foundation\Application;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SecureOtpServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('laravel-secure-otp')
            ->hasConfigFile('secure-otp')
            ->hasMigration('create_secure_otps_table')
            ->runsMigrations()
            ->hasCommand(CleanOtpsCommand::class);
    }

    public function packageRegistered(): void
    {
        // Register SecureOtpService as singleton
        $this->app->singleton(SecureOtpService::class, function (Application $app) {
            return new SecureOtpService;
        });

        // Register alias for easier access
        $this->app->alias(SecureOtpService::class, 'secure-otp');
    }
}
