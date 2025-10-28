<?php

use Biponix\SecureOtp\Models\SecureOtp;
use Carbon\Carbon;

use function Pest\Laravel\artisan;

beforeEach(function () {
    // Clean up existing data
    SecureOtp::query()->delete();
});

test('it deletes expired OTPs successfully', function () {
    // Create expired OTP (older than 24 hours)
    SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => Carbon::now()->subHours(25),
        'created_at' => Carbon::now()->subHours(26),
    ]);

    // Create recent OTP
    SecureOtp::create([
        'identifier' => 'test2@example.com',
        'code_hash' => hash('sha256', '654321'),
        'attempts' => 0,
        'expires_at' => Carbon::now()->addMinutes(5),
        'created_at' => Carbon::now(),
    ]);

    artisan('secure-otp:clean --force')
        ->expectsOutput('Cleaning up expired OTPs...')
        ->assertExitCode(0);

    expect(SecureOtp::count())->toBe(1)
        ->and(SecureOtp::first()->identifier)->toBe('test2@example.com');
});

test('it shows message when no expired OTPs found', function () {
    // Create only recent OTP
    SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => Carbon::now()->addMinutes(5),
        'created_at' => Carbon::now(),
    ]);

    artisan('secure-otp:clean --force')
        ->expectsOutput('Cleaning up expired OTPs...')
        ->expectsOutput('No expired OTPs found.')
        ->assertExitCode(0);

    expect(SecureOtp::count())->toBe(1);
});

test('it requires --force flag in production', function () {
    // Mock production environment
    app()->detectEnvironment(fn () => 'production');

    artisan('secure-otp:clean')
        ->expectsOutput('Use --force to run in production environment')
        ->assertExitCode(1);
});

test('it runs without --force flag in non-production', function () {
    // Ensure we're not in production
    app()->detectEnvironment(fn () => 'testing');

    // Create expired OTP
    SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => Carbon::now()->subHours(25),
        'created_at' => Carbon::now()->subHours(26),
    ]);

    artisan('secure-otp:clean')
        ->expectsOutput('Cleaning up expired OTPs...')
        ->assertExitCode(0);

    expect(SecureOtp::count())->toBe(0);
});
