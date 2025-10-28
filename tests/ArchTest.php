<?php

// Prevent debugging functions in production code
arch('it will not use debugging functions')
    ->expect(['dd', 'dump', 'ray'])
    ->each->not->toBeUsed();

// Ensure all models extend the base Eloquent Model
arch('models should extend base model')
    ->expect('Biponix\SecureOtp\Models')
    ->toExtend('Illuminate\Database\Eloquent\Model');

// Ensure commands have proper suffix
arch('commands should have Command suffix')
    ->expect('Biponix\SecureOtp\Commands')
    ->toHaveSuffix('Command');

// Ensure commands extend the base Command class
arch('commands should extend base command')
    ->expect('Biponix\SecureOtp\Commands')
    ->toExtend('Illuminate\Console\Command');

// Ensure notifications extend base Notification class
arch('notifications should extend base notification')
    ->expect('Biponix\SecureOtp\Notifications')
    ->toExtend('Illuminate\Notifications\Notification');

// Ensure facades extend base Facade class
arch('facades should extend base facade')
    ->expect('Biponix\SecureOtp\Facades')
    ->toExtend('Illuminate\Support\Facades\Facade');

// Ensure no dangerous globals are used
arch('it will not use dangerous globals')
    ->expect(['eval', 'extract', 'compact'])
    ->each->not->toBeUsed();

// Ensure classes use strict types
arch('strict types should be used')
    ->expect('Biponix\SecureOtp')
    ->toUseStrictTypes();

// Ensure services are final (prevent inheritance complexity)
arch('services should be final')
    ->expect('Biponix\SecureOtp\Services')
    ->toBeFinal();

// Ensure service provider extends base PackageServiceProvider
arch('service provider should extend package service provider')
    ->expect('Biponix\SecureOtp\SecureOtpServiceProvider')
    ->toExtend('Spatie\LaravelPackageTools\PackageServiceProvider');
