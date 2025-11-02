<?php

declare(strict_types=1);

namespace Biponix\SecureOtp;

use Biponix\SecureOtp\Commands\CleanOtpsCommand;
use Biponix\SecureOtp\Contracts\OtpService;
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

    /**
     * @codeCoverageIgnore
     */
    public function packageRegistered(): void
    {
        $this->app->singleton(OtpService::class, function (Application $app) {
            return new SecureOtpService;
        });

        $this->app->alias(OtpService::class, 'secure-otp');
    }
}
