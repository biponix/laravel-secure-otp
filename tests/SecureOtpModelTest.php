<?php

use Biponix\SecureOtp\Models\SecureOtp;
use Illuminate\Support\Carbon;

beforeEach(function () {
    SecureOtp::query()->delete();
});

test('it uses UUID for primary key', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->id)->toBeString()
        ->and(strlen($otp->id))->toBe(36); // UUID length
});

test('it casts dates correctly', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->expires_at)->toBeInstanceOf(Carbon::class)
        ->and($otp->created_at)->toBeInstanceOf(Carbon::class);
});

test('isVerified() returns false when not verified', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->isVerified())->toBeFalse();
});

test('isVerified() returns true when verified', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'verified_at' => now(),
        'created_at' => now(),
    ]);

    expect($otp->isVerified())->toBeTrue();
});

test('isExpired() returns true when expired', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->subMinutes(10),
        'created_at' => now()->subMinutes(20),
    ]);

    expect($otp->isExpired())->toBeTrue();
});

test('isExpired() returns false when not expired', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->isExpired())->toBeFalse();
});

test('hasMaxAttemptsReached() returns false when below max', function () {
    config(['secure-otp.max_attempts' => 3]);

    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 2,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->hasMaxAttemptsReached())->toBeFalse();
});

test('hasMaxAttemptsReached() returns true when at max', function () {
    config(['secure-otp.max_attempts' => 3]);

    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 3,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->hasMaxAttemptsReached())->toBeTrue();
});

test('hasMaxAttemptsReached() returns true when exceeded', function () {
    config(['secure-otp.max_attempts' => 3]);

    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 5,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->hasMaxAttemptsReached())->toBeTrue();
});

test('markAsVerified() marks OTP as verified', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->verified_at)->toBeNull();

    $otp->markAsVerified();
    $otp->refresh();

    expect($otp->verified_at)->not->toBeNull()
        ->and($otp->isVerified())->toBeTrue();
});

test('incrementAttempts() increments attempts counter', function () {
    $otp = SecureOtp::create([
        'identifier' => 'test@example.com',
        'code_hash' => hash('sha256', '123456'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    expect($otp->attempts)->toBe(0);

    $otp->incrementAttempts();
    $otp->refresh();

    expect($otp->attempts)->toBe(1);

    $otp->incrementAttempts();
    $otp->refresh();

    expect($otp->attempts)->toBe(2);
});

test('valid() scope filters unverified and unexpired OTPs', function () {
    // Create expired OTP
    SecureOtp::create([
        'identifier' => 'expired@example.com',
        'code_hash' => hash('sha256', '111111'),
        'attempts' => 0,
        'expires_at' => now()->subMinutes(10),
        'created_at' => now()->subMinutes(20),
    ]);

    // Create verified OTP
    SecureOtp::create([
        'identifier' => 'verified@example.com',
        'code_hash' => hash('sha256', '222222'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'verified_at' => now(),
        'created_at' => now(),
    ]);

    // Create valid OTP
    SecureOtp::create([
        'identifier' => 'valid@example.com',
        'code_hash' => hash('sha256', '333333'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    $validOtps = SecureOtp::valid()->get();

    expect($validOtps)->toHaveCount(1)
        ->and($validOtps->first()->identifier)->toBe('valid@example.com');
});

test('forIdentifier() scope filters by identifier', function () {
    SecureOtp::create([
        'identifier' => 'user1@example.com',
        'code_hash' => hash('sha256', '111111'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    SecureOtp::create([
        'identifier' => 'user2@example.com',
        'code_hash' => hash('sha256', '222222'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    $user1Otps = SecureOtp::forIdentifier('user1@example.com')->get();

    expect($user1Otps)->toHaveCount(1)
        ->and($user1Otps->first()->identifier)->toBe('user1@example.com');
});

test('expired() scope filters expired OTPs', function () {
    // Create expired OTP
    SecureOtp::create([
        'identifier' => 'expired@example.com',
        'code_hash' => hash('sha256', '111111'),
        'attempts' => 0,
        'expires_at' => now()->subMinutes(10),
        'created_at' => now()->subMinutes(20),
    ]);

    // Create valid OTP
    SecureOtp::create([
        'identifier' => 'valid@example.com',
        'code_hash' => hash('sha256', '222222'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    $expiredOtps = SecureOtp::expired()->get();

    expect($expiredOtps)->toHaveCount(1)
        ->and($expiredOtps->first()->identifier)->toBe('expired@example.com');
});

test('scopes can be chained together', function () {
    // Create OTP for user1 (valid)
    SecureOtp::create([
        'identifier' => 'user1@example.com',
        'code_hash' => hash('sha256', '111111'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    // Create OTP for user1 (verified)
    SecureOtp::create([
        'identifier' => 'user1@example.com',
        'code_hash' => hash('sha256', '222222'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'verified_at' => now(),
        'created_at' => now(),
    ]);

    // Create OTP for user2 (valid)
    SecureOtp::create([
        'identifier' => 'user2@example.com',
        'code_hash' => hash('sha256', '333333'),
        'attempts' => 0,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
    ]);

    $user1ValidOtps = SecureOtp::forIdentifier('user1@example.com')
        ->valid()
        ->get();

    expect($user1ValidOtps)->toHaveCount(1);
});
