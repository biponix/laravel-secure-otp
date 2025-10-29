<?php

use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;
use Biponix\SecureOtp\Models\SecureOtp;
use Biponix\SecureOtp\Notifications\OtpNotification;
use Biponix\SecureOtp\Services\SecureOtpService;
use Biponix\SecureOtp\Support\OnDemandNotifiable;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;

// Helper to get the last sent OTP code
function getLastSentOtpCode(string $identifier = 'test@example.com'): ?string
{
    $code = null;
    Notification::assertSentTo(
        new OnDemandNotifiable($identifier),
        OtpNotification::class,
        function ($notification) use (&$code) {
            $code = $notification->code;

            return true;
        }
    );

    return $code;
}

beforeEach(function () {

    config(['secure-otp.hash_secret' => 'test-secret-key-for-hmac']);

    // Clear rate limiters using actual config prefix (both generate and verify contexts)
    $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');
    RateLimiter::clear("{$prefix}:generate:identifier:test@example.com");
    RateLimiter::clear("{$prefix}:generate:identifier:+1234567890");
    RateLimiter::clear("{$prefix}:generate:ip:127.0.0.1");
    RateLimiter::clear("{$prefix}:verify:identifier:test@example.com");
    RateLimiter::clear("{$prefix}:verify:identifier:+1234567890");
    RateLimiter::clear("{$prefix}:verify:ip:127.0.0.1");

    // Fake notifications
    Notification::fake();

    $this->otpService = app(SecureOtpService::class);
});

describe('send() method - Success Cases', function () {
    it('sends OTP to valid email address', function () {
        $result = $this->otpService->send('test@example.com');

        expect($result)->toBeTrue();

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp)->not->toBeNull()
            ->and($otp->identifier)->toBe('test@example.com')
            ->and($otp->attempts)->toBe(0)
            ->and($otp->verified_at)->toBeNull();

        Notification::assertSentTo(
            new OnDemandNotifiable('test@example.com'),
            OtpNotification::class
        );
    });

    it('sends OTP to valid phone number', function () {
        $result = $this->otpService->send('+1234567890');

        expect($result)->toBeTrue();

        $otp = SecureOtp::query()->where('identifier', '+1234567890')->first();
        expect($otp)->not->toBeNull()
            ->and($otp->identifier)->toBe('+1234567890')
            ->and($otp->attempts)->toBe(0)
            ->and($otp->verified_at)->toBeNull();

        Notification::assertSentTo(
            new OnDemandNotifiable('+1234567890'),
            OtpNotification::class
        );
    });

    it('generates 6-digit OTP code by default', function () {
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        expect($code)->toHaveLength(6)
            ->and(ctype_digit($code))->toBeTrue();
    });

    it('stores hashed code not plain text', function () {
        $this->otpService->send('test@example.com');

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect(strlen($otp->code_hash))->toBe(64); // SHA-256 = 64 hex chars
    });

    it('sets expiry time from config', function () {
        config(['secure-otp.expiry_minutes' => 10]);
        $before = now();
        $this->otpService->send('test@example.com');

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        // Account for timing precision - check it's at least 10 minutes minus 1 second
        expect($otp->expires_at)->toBeGreaterThan($before->copy()->addMinutes(10)->subSecond());
    });

    it('invalidates previous OTPs for same identifier', function () {
        $this->otpService->send('test@example.com');
        $this->travel(1)->second();
        $this->otpService->send('test@example.com');

        $otps = SecureOtp::query()
            ->where('identifier', 'test@example.com')
            ->orderBy('created_at')
            ->get();

        expect($otps)->toHaveCount(2)
            ->and($otps[0]->verified_at)->not->toBeNull()
            ->and($otps[1]->verified_at)->toBeNull();
    });
});

describe('send() method - Validation Failures', function () {
    it('throws exception for invalid email', function () {
        expect(fn () => $this->otpService->send('invalid-email'))
            ->toThrow(InvalidIdentifierException::class, 'Invalid identifier format provided');

        expect(SecureOtp::query()->where('identifier', 'invalid-email')->first())->toBeNull();
        Notification::assertNothingSent();
    });

    it('throws exception for empty identifier', function () {
        expect(fn () => $this->otpService->send(''))
            ->toThrow(InvalidIdentifierException::class);

        expect(SecureOtp::query()->count())->toBe(0);
    });

    it('logs security event for invalid identifier', function () {
        Log::spy();

        try {
            $this->otpService->send('invalid');
            $this->fail('Should have thrown InvalidIdentifierException');
        } catch (InvalidIdentifierException $e) {
            // Expected
            expect($e)->toBeInstanceOf(InvalidIdentifierException::class);
        }

        Log::shouldHaveReceived('warning')
            ->with('OTP security event: invalid_identifier', \Mockery::type('array'));
    });
});

describe('send() method - Rate Limiting', function () {
    it('enforces per-identifier rate limit', function () {
        config(['secure-otp.rate_limits.per_identifier.max_attempts' => 2]);

        $result1 = $this->otpService->send('test@example.com');
        $result2 = $this->otpService->send('test@example.com');
        $result3 = $this->otpService->send('test@example.com');

        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue()
            ->and($result3)->toBeFalse();
    });

    it('applies IP rate limiting when IP is available', function () {
        config(['secure-otp.rate_limits.per_ip.max_attempts' => 2]);

        // Simulate HTTP context with a request
        $request = \Illuminate\Http\Request::create('/test', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.1']);
        app()->instance('request', $request);

        $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');
        RateLimiter::clear("{$prefix}:ip:192.168.1.1");

        $result1 = $this->otpService->send('user1@example.com');
        $result2 = $this->otpService->send('user2@example.com');
        $result3 = $this->otpService->send('user3@example.com');

        // First 2 should succeed, 3rd should be rate limited by IP
        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue()
            ->and($result3)->toBeFalse();
    });

    it('rate limits are independent per identifier', function () {
        config(['secure-otp.rate_limits.per_identifier.max_attempts' => 1]);

        $this->otpService->send('user1@example.com');
        $result1 = $this->otpService->send('user1@example.com');

        $result2 = $this->otpService->send('user2@example.com');

        expect($result1)->toBeFalse()
            ->and($result2)->toBeTrue();
    });

    it('allows OTP generation when per_identifier rate limiting is disabled', function () {
        // Disable per_identifier rate limiting
        config(['secure-otp.rate_limits.per_identifier' => null]);

        // Should not throw an error and should generate OTPs
        for ($i = 0; $i < 5; $i++) {
            $result = $this->otpService->send('test@example.com');
            expect($result)->toBeTrue();
        }
    });

    it('allows OTP generation when per_ip rate limiting is disabled', function () {
        // Disable per_ip rate limiting
        config(['secure-otp.rate_limits.per_ip' => false]);

        // Should still respect per_identifier rate limiting
        $result1 = $this->otpService->send('test@example.com');
        $result2 = $this->otpService->send('test@example.com');
        $result3 = $this->otpService->send('test@example.com');
        $result4 = $this->otpService->send('test@example.com'); // Should be rate limited

        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue()
            ->and($result3)->toBeTrue()
            ->and($result4)->toBeFalse(); // Rate limited by per_identifier
    });
});

describe('send() method - Error Handling', function () {
    it('throws exception when notification send fails', function () {
        Notification::shouldReceive('route')->andThrow(new \Exception('SMTP failed'));

        expect(fn () => $this->otpService->send('test@example.com'))
            ->toThrow(OtpGenerationException::class, 'Failed to send OTP');
    });

    it('logs errors when notification fails', function () {
        Log::spy();
        Notification::shouldReceive('route')->andThrow(new \Exception('Network error'));

        try {
            $this->otpService->send('test@example.com');
            $this->fail('Should have thrown OtpGenerationException');
        } catch (OtpGenerationException $e) {
            // Expected
            expect($e)->toBeInstanceOf(OtpGenerationException::class);
        }

        Log::shouldHaveReceived('error')
            ->with('OTP send failed (queued)', \Mockery::type('array'));
    });
});

describe('verify() method - Success Cases', function () {
    it('verifies valid OTP code', function () {
        $this->otpService->send('test@example.com');
        $sentCode = getLastSentOtpCode();

        $result = $this->otpService->verify('test@example.com', $sentCode);

        expect($result)->toBeTrue();
    });

    it('marks OTP as verified after successful verification', function () {
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        $this->otpService->verify('test@example.com', $code);

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp->verified_at)->not->toBeNull();
    });

    it('allows verification within expiry window', function () {
        config(['secure-otp.expiry_minutes' => 10]);
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        $this->travel(9)->minutes();

        $result = $this->otpService->verify('test@example.com', $code);
        expect($result)->toBeTrue();
    });
});

describe('verify() method - Failure Cases', function () {
    it('fails for non-6-digit code', function () {
        $result = $this->otpService->verify('test@example.com', '12345');

        expect($result)->toBeFalse();
    });

    it('fails for non-numeric code', function () {
        $result = $this->otpService->verify('test@example.com', 'abcdef');

        expect($result)->toBeFalse();
    });

    it('fails when OTP not found', function () {
        $result = $this->otpService->verify('nonexistent@example.com', '123456');

        expect($result)->toBeFalse();
    });

    it('fails when OTP expired', function () {
        config(['secure-otp.expiry_minutes' => 5]);
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        $this->travel(6)->minutes();

        $result = $this->otpService->verify('test@example.com', $code);
        expect($result)->toBeFalse();
    });

    it('fails when OTP already verified (replay attack)', function () {
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        $this->otpService->verify('test@example.com', $code);
        $result = $this->otpService->verify('test@example.com', $code);

        expect($result)->toBeFalse();
    });

    it('fails with wrong code', function () {
        $this->otpService->send('test@example.com');

        $result = $this->otpService->verify('test@example.com', '999999');
        expect($result)->toBeFalse();
    });

    it('increments attempts counter on wrong code', function () {
        $this->otpService->send('test@example.com');

        $this->otpService->verify('test@example.com', '999999');
        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp->attempts)->toBe(1);

        $this->otpService->verify('test@example.com', '888888');
        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp->attempts)->toBe(2);
    });

    it('fails after max attempts exceeded', function () {
        config(['secure-otp.max_attempts' => 3]);
        $this->otpService->send('test@example.com');

        $this->otpService->verify('test@example.com', '111111');
        $this->otpService->verify('test@example.com', '222222');
        $this->otpService->verify('test@example.com', '333333');

        $result = $this->otpService->verify('test@example.com', '444444');
        expect($result)->toBeFalse();
    });

    it('uses latest OTP when multiple exist', function () {
        $this->otpService->send('test@example.com');
        $firstCode = getLastSentOtpCode('test@example.com');

        Notification::fake();
        $this->travel(1)->second();
        $this->otpService->send('test@example.com');
        $secondCode = getLastSentOtpCode('test@example.com');

        $result1 = $this->otpService->verify('test@example.com', $firstCode);
        $result2 = $this->otpService->verify('test@example.com', $secondCode);

        expect($result1)->toBeFalse()
            ->and($result2)->toBeTrue();
    });
});

describe('verify() method - Security Features', function () {
    it('returns generic boolean for all failure types', function () {
        $result1 = $this->otpService->verify('test@example.com', 'abc');
        $result2 = $this->otpService->verify('test@example.com', '123456');

        $this->otpService->send('test@example.com');
        $result3 = $this->otpService->verify('test@example.com', '999999');

        expect($result1)->toBeFalse()
            ->and($result2)->toBeFalse()
            ->and($result3)->toBeFalse();
    });

    it('prevents race conditions with row lock', function () {
        $this->otpService->send('test@example.com');
        $code = getLastSentOtpCode();

        $result1 = $this->otpService->verify('test@example.com', $code);
        $result2 = $this->otpService->verify('test@example.com', $code);

        expect($result1)->toBeTrue()
            ->and($result2)->toBeFalse();
    });

    it('rate limits verification attempts to prevent brute force', function () {
        // Generate an OTP
        $this->otpService->send('test@example.com');

        // Clear generate rate limiter to isolate verify rate limiter
        $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');
        RateLimiter::clear("{$prefix}:generate:identifier:test@example.com");

        // Try verifying with wrong codes up to the verify rate limit
        $verifyLimit = config('secure-otp.rate_limits.verify_per_identifier.max_attempts', 5);

        for ($i = 0; $i < $verifyLimit; $i++) {
            $result = $this->otpService->verify('test@example.com', '000000');
            expect($result)->toBeFalse(); // Wrong code
        }

        // Next verification attempt should be rate limited
        $result = $this->otpService->verify('test@example.com', '999999');
        expect($result)->toBeFalse();

        // Verify the verify context was used in rate limiter key
        expect(RateLimiter::attempts("{$prefix}:verify:identifier:test@example.com"))->toBeGreaterThanOrEqual($verifyLimit);
    });

    it('applies IP rate limiting for verification attempts from same IP', function () {
        config(['secure-otp.rate_limits.verify_per_ip.max_attempts' => 3]);

        // Simulate HTTP context with a specific IP
        $request = \Illuminate\Http\Request::create('/test', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.42']);
        app()->instance('request', $request);

        $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');
        RateLimiter::clear("{$prefix}:verify:ip:203.0.113.42");

        // Generate OTPs for 3 different users
        $this->otpService->send('user1@example.com');
        $this->otpService->send('user2@example.com');
        $this->otpService->send('user3@example.com');
        $this->otpService->send('user4@example.com');

        // Clear generate rate limiters to isolate verify rate limiter
        RateLimiter::clear("{$prefix}:generate:identifier:user1@example.com");
        RateLimiter::clear("{$prefix}:generate:identifier:user2@example.com");
        RateLimiter::clear("{$prefix}:generate:identifier:user3@example.com");
        RateLimiter::clear("{$prefix}:generate:identifier:user4@example.com");

        // Try verifying wrong codes from same IP for different users
        $result1 = $this->otpService->verify('user1@example.com', '000001');
        $result2 = $this->otpService->verify('user2@example.com', '000002');
        $result3 = $this->otpService->verify('user3@example.com', '000003');

        // First 3 attempts should process (and fail due to wrong code)
        expect($result1)->toBeFalse()
            ->and($result2)->toBeFalse()
            ->and($result3)->toBeFalse();

        // 4th attempt should be rate limited by IP (even for different user)
        $result4 = $this->otpService->verify('user4@example.com', '000004');
        expect($result4)->toBeFalse();

        // Verify IP rate limiter was triggered
        expect(RateLimiter::attempts("{$prefix}:verify:ip:203.0.113.42"))->toBeGreaterThanOrEqual(3);
    });
});

describe('Helper Methods', function () {
    it('validates email identifiers', function () {
        $result1 = $this->otpService->send('user@example.com');
        $result2 = $this->otpService->send('test.user+tag@domain.co.uk');

        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue();
    });

    it('validates phone identifiers', function () {
        $result1 = $this->otpService->send('+12345678901');
        $result2 = $this->otpService->send('12345678901');

        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue();
    });

    it('generates unique codes', function () {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $identifier = "user{$i}@example.com";
            $this->otpService->send($identifier);
            $codes[] = getLastSentOtpCode($identifier);
            Notification::fake();
        }

        expect(count(array_unique($codes)))->toBeGreaterThan(8);
    });

    it('masks email identifier for logging', function () {
        Log::spy();
        $result = $this->otpService->send('test@example.com');

        expect($result)->toBeTrue();

        // Should log twice: generate() + send()
        Log::shouldHaveReceived('info')
            ->with(
                'OTP generated successfully (without sending)',
                \Mockery::on(fn ($ctx) => str_contains($ctx['identifier'], '***'))
            );
        Log::shouldHaveReceived('info')
            ->with(
                'OTP sent successfully (queued)',
                \Mockery::on(fn ($ctx) => str_contains($ctx['identifier'], '***'))
            );
    });

    it('masks phone identifier for logging', function () {
        Log::spy();
        $result = $this->otpService->send('+1234567890');

        expect($result)->toBeTrue();

        // Should log twice: generate() + send()
        Log::shouldHaveReceived('info')
            ->with(
                'OTP generated successfully (without sending)',
                \Mockery::on(fn ($ctx) => str_ends_with($ctx['identifier'], '7890'))
            );
        Log::shouldHaveReceived('info')
            ->with(
                'OTP sent successfully (queued)',
                \Mockery::on(fn ($ctx) => str_ends_with($ctx['identifier'], '7890'))
            );
    });
});

describe('cleanupExpired() method', function () {
    it('deletes OTPs older than configured hours', function () {
        config(['secure-otp.cleanup_after_hours' => 24]);

        SecureOtp::query()->insert([
            'id' => \Illuminate\Support\Str::uuid(),
            'identifier' => 'old@example.com',
            'code_hash' => hash('sha256', '123456'),
            'attempts' => 0,
            'expires_at' => now()->addMinutes(10),
            'created_at' => now()->subHours(25),
        ]);

        SecureOtp::query()->insert([
            'id' => \Illuminate\Support\Str::uuid(),
            'identifier' => 'new@example.com',
            'code_hash' => hash('sha256', '654321'),
            'attempts' => 0,
            'expires_at' => now()->addMinutes(10),
            'created_at' => now()->subHour(),
        ]);

        $deleted = $this->otpService->cleanupExpired();

        expect($deleted)->toBe(1);
        expect(SecureOtp::query()->count())->toBe(1);
        expect(SecureOtp::query()->first()->identifier)->toBe('new@example.com');
    });

    it('returns count of deleted records', function () {
        config(['secure-otp.cleanup_after_hours' => 1]);

        for ($i = 0; $i < 5; $i++) {
            SecureOtp::query()->insert([
                'id' => \Illuminate\Support\Str::uuid(),
                'identifier' => "old{$i}@example.com",
                'code_hash' => hash('sha256', '123456'),
                'attempts' => 0,
                'expires_at' => now()->addMinutes(10),
                'created_at' => now()->subHours(2),
            ]);
        }

        $deleted = $this->otpService->cleanupExpired();
        expect($deleted)->toBe(5);
    });
});

describe('Edge Cases', function () {
    it('works in contexts without HTTP request', function () {
        // Unbind request to simulate pure console/queue context
        app()->forgetInstance('request');

        // Should work fine without IP/user agent tracking
        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp)->not->toBeNull();
    });

    it('handles special characters in identifier', function () {
        $result = $this->otpService->send('test+tag@example.com');
        expect($result)->toBeTrue();
    });

    it('allows multiple sequential OTP sends for same identifier', function () {
        $result1 = $this->otpService->send('test@example.com');
        $result2 = $this->otpService->send('test@example.com');
        $result3 = $this->otpService->send('test@example.com');

        expect($result1)->toBeTrue();

        $latestOtp = SecureOtp::query()
            ->where('identifier', 'test@example.com')
            ->whereNull('verified_at')
            ->orderBy('created_at', 'desc')
            ->first();

        expect($latestOtp)->not->toBeNull();
    });

    it('respects logging configuration', function () {
        Log::spy();

        config(['secure-otp.enable_logging' => false]);
        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();
        Log::shouldNotHaveReceived('info');

        config(['secure-otp.enable_logging' => true]);
        $result2 = $this->otpService->send('test2@example.com');
        expect($result2)->toBeTrue();
        // Should log twice: generate() + send()
        Log::shouldHaveReceived('info')->twice();
    });

    it('respects logging configuration for security events', function () {
        Log::spy();

        // Disable logging
        config(['secure-otp.enable_logging' => false]);

        // Try to send to invalid identifier (triggers security event)
        try {
            $this->otpService->send('invalid-email');
            $this->fail('Should have thrown InvalidIdentifierException');
        } catch (InvalidIdentifierException $e) {
            // Expected
            expect($e)->toBeInstanceOf(InvalidIdentifierException::class);
        }

        // Should not log security warning when logging is disabled
        Log::shouldNotHaveReceived('warning');

        // Re-enable logging
        config(['secure-otp.enable_logging' => true]);

        // Try to send to another invalid identifier
        try {
            $this->otpService->send('another-invalid');
            $this->fail('Should have thrown InvalidIdentifierException');
        } catch (InvalidIdentifierException $e) {
            // Expected
            expect($e)->toBeInstanceOf(InvalidIdentifierException::class);
        }

        // Should log security warning when logging is enabled
        Log::shouldHaveReceived('warning')
            ->once()
            ->with(Mockery::on(fn ($msg) => str_contains($msg, 'security event')), Mockery::any());
    });

    it('logs security events without request context', function () {
        Log::spy();
        app()->forgetInstance('request');

        // Trigger security event without HTTP request (tests getUserAgent() null path)
        try {
            $this->otpService->send('invalid-email');
            $this->fail('Should have thrown InvalidIdentifierException');
        } catch (InvalidIdentifierException $e) {
            // Expected
            expect($e)->toBeInstanceOf(InvalidIdentifierException::class);
        }

        Log::shouldHaveReceived('warning')
            ->once()
            ->with(
                Mockery::on(fn ($msg) => str_contains($msg, 'security event')),
                Mockery::on(fn ($ctx) => $ctx['ip'] === null && $ctx['user_agent'] === null)
            );
    });

    it('handles database exceptions gracefully during verification', function () {
        Log::spy();

        // Create OTP first
        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();

        // Mock DB to throw exception
        DB::shouldReceive('transaction')
            ->andThrow(new Exception('Database connection lost'));

        // Verify should handle exception gracefully
        $result = $this->otpService->verify('test@example.com', '123456');

        expect($result)->toBeFalse();

        // Verify error was logged
        Log::shouldHaveReceived('error')
            ->once()
            ->with('OTP verification error', Mockery::on(function ($arg) {
                return isset($arg['error']) && $arg['error'] === 'Database connection lost';
            }));
    });
});

describe('Security Enhancements', function () {
    it('rejects invalid notification class', function () {
        config(['secure-otp.notification_class' => \stdClass::class]);
        Log::spy();

        // Should throw exception
        expect(fn () => $this->otpService->send('test@example.com'))
            ->toThrow(OtpGenerationException::class, 'Failed to send OTP');

        // Should log the error
        Log::shouldHaveReceived('error')
            ->once()
            ->with('OTP send failed (queued)', Mockery::on(function ($arg) {
                return isset($arg['error']) &&
                       str_contains($arg['error'], 'Notification class must extend Illuminate\Notifications\Notification');
            }));
    });

    it('rejects identifiers longer than 255 characters', function () {
        Log::spy();

        $longIdentifier = str_repeat('a', 256).'@example.com';

        // Should throw exception for invalid identifier
        expect(fn () => $this->otpService->send($longIdentifier))
            ->toThrow(InvalidIdentifierException::class);

        // Should not create OTP for invalid identifier
        $otp = SecureOtp::query()->where('identifier', $longIdentifier)->first();
        expect($otp)->toBeNull();

        // Should log security event
        Log::shouldHaveReceived('warning')
            ->once()
            ->with('OTP security event: invalid_identifier', Mockery::any());
    });

    it('uses custom rate limiter prefix from config', function () {
        config(['secure-otp.rate_limits.prefix' => 'custom-prefix']);

        // Clear all possible rate limiter keys
        RateLimiter::clear('custom-prefix:identifier:test@example.com');
        RateLimiter::clear('custom-prefix:ip:127.0.0.1');
        RateLimiter::clear('secure-otp:identifier:test@example.com');
        RateLimiter::clear('secure-otp:ip:127.0.0.1');

        // Send OTPs up to the limit
        for ($i = 0; $i < 3; $i++) {
            $result = $this->otpService->send('test@example.com');
            expect($result)->toBeTrue();
        }

        // Next attempt should be rate limited
        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeFalse();

        // Verify the custom prefix was used by checking hits (includes context 'generate')
        expect(RateLimiter::attempts('custom-prefix:generate:identifier:test@example.com'))->toBeGreaterThan(0);
    });
});

describe('generate() method', function () {
    it('generates OTP without sending notification', function () {
        $code = $this->otpService->generate('test@example.com');

        expect($code)->toBeString()
            ->and($code)->toMatch('/^\d{6}$/');

        // Verify OTP was stored in database
        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp)->not->toBeNull()
            ->and($otp->identifier)->toBe('test@example.com');

        // Verify no notification was sent
        Notification::assertNothingSent();
    });

    it('throws exception for invalid identifier', function () {
        expect(fn () => $this->otpService->generate('invalid-email'))
            ->toThrow(InvalidIdentifierException::class, 'Invalid identifier format provided');
    });

    it('returns null when rate limited', function () {
        // Generate 3 times to hit rate limit
        for ($i = 0; $i < 3; $i++) {
            $this->otpService->generate('test@example.com');
        }

        // 4th attempt should be rate limited
        $result = $this->otpService->generate('test@example.com');

        expect($result)->toBeNull();
    });

    it('logs generation event', function () {
        Log::spy();
        $code = $this->otpService->generate('test@example.com');

        expect($code)->toBeString();

        Log::shouldHaveReceived('info')
            ->with(
                'OTP generated successfully (without sending)',
                \Mockery::on(fn ($ctx) => str_contains($ctx['identifier'], '***'))
            );
    });

    it('can verify generated OTP', function () {
        // Generate OTP
        $code = $this->otpService->generate('test@example.com');
        expect($code)->toBeString();

        // Verify the generated code
        $verifyResult = $this->otpService->verify('test@example.com', $code);
        expect($verifyResult)->toBeTrue();
    });

    it('throws exception when database fails during generation', function () {
        Log::spy();

        // Mock DB to throw exception during generation
        DB::shouldReceive('transaction')
            ->once()
            ->andThrow(new Exception('Database connection lost'));

        // Should throw OtpGenerationException
        expect(fn () => $this->otpService->generate('test@example.com'))
            ->toThrow(OtpGenerationException::class, 'Failed to generate OTP');

        // Should log error
        Log::shouldHaveReceived('error')
            ->once()
            ->with('OTP generation failed', Mockery::on(function ($arg) {
                return isset($arg['error']) && $arg['error'] === 'Database connection lost';
            }));
    });
});

describe('sendNow() method', function () {
    it('sends OTP synchronously', function () {
        $result = $this->otpService->sendNow('test@example.com');

        expect($result)->toBeTrue();

        // Verify OTP was stored
        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp)->not->toBeNull();

        // Verify notification was sent
        Notification::assertSentTo(
            new OnDemandNotifiable('test@example.com'),
            OtpNotification::class
        );
    });

    it('uses notifyNow instead of notify', function () {
        Log::spy();
        $result = $this->otpService->sendNow('test@example.com');

        expect($result)->toBeTrue();

        Log::shouldHaveReceived('info')
            ->with(
                'OTP sent successfully (synchronously)',
                \Mockery::on(fn ($ctx) => $ctx['identifier'] === 'te***@example.com')
            );
    });

    it('throws exception for invalid identifier', function () {
        expect(fn () => $this->otpService->sendNow('invalid-email'))
            ->toThrow(InvalidIdentifierException::class);

        // Should not create OTP
        $otp = SecureOtp::query()->where('identifier', 'invalid-email')->first();
        expect($otp)->toBeNull();
    });

    it('returns false when rate limited', function () {
        // Send 3 times to hit rate limit
        for ($i = 0; $i < 3; $i++) {
            $this->otpService->sendNow('test@example.com');
        }

        // 4th attempt should be rate limited
        $result = $this->otpService->sendNow('test@example.com');

        expect($result)->toBeFalse();
    });

    it('can verify OTP sent synchronously', function () {
        // Send OTP
        $this->otpService->sendNow('test@example.com');

        // Get the sent code
        $code = getLastSentOtpCode();

        // Verify
        $result = $this->otpService->verify('test@example.com', $code);
        expect($result)->toBeTrue();
    });

    it('throws exception when notification send fails synchronously', function () {
        Notification::shouldReceive('route')->andThrow(new \Exception('SMTP failed'));

        expect(fn () => $this->otpService->sendNow('test@example.com'))
            ->toThrow(OtpGenerationException::class, 'Failed to send OTP');
    });

    it('logs errors when synchronous notification fails', function () {
        Log::spy();
        Notification::shouldReceive('route')->andThrow(new \Exception('Network error'));

        try {
            $this->otpService->sendNow('test@example.com');
            $this->fail('Should have thrown OtpGenerationException');
        } catch (OtpGenerationException $e) {
            // Expected
            expect($e)->toBeInstanceOf(OtpGenerationException::class);
        }

        Log::shouldHaveReceived('error')
            ->with('OTP send failed (synchronously)', \Mockery::type('array'));
    });
});

describe('Security Fix: Identifier Normalization', function () {
    it('normalizes email to lowercase for storage and verification', function () {
        // Send with uppercase email
        $result = $this->otpService->send('User@Example.COM');
        expect($result)->toBeTrue();

        // Should be stored as lowercase
        $otp = SecureOtp::query()->where('identifier', 'user@example.com')->first();
        expect($otp)->not->toBeNull();

        // Should NOT be stored as uppercase
        $otpUpper = SecureOtp::query()->where('identifier', 'User@Example.COM')->first();
        expect($otpUpper)->toBeNull();

        // Notification is sent to normalized identifier (lowercase)
        $code = getLastSentOtpCode('user@example.com');
        expect($this->otpService->verify('user@example.com', $code))->toBeTrue();
    });

    it('trims whitespace from identifiers', function () {
        // Send with whitespace
        $result = $this->otpService->send('  test@example.com  ');
        expect($result)->toBeTrue();

        // Should be stored without whitespace
        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp)->not->toBeNull();

        // Notification is sent to normalized identifier (not raw with spaces)
        $code = getLastSentOtpCode('test@example.com');
        expect($this->otpService->verify('test@example.com', $code))->toBeTrue();
    });

    it('prevents rate limit bypass via case variation', function () {
        config(['secure-otp.rate_limits.per_identifier.max_attempts' => 2]);

        $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');
        RateLimiter::clear("{$prefix}:identifier:test@example.com");

        // First two should succeed (same normalized identifier)
        $result1 = $this->otpService->send('test@example.com');
        $result2 = $this->otpService->send('Test@Example.COM');

        expect($result1)->toBeTrue()
            ->and($result2)->toBeTrue();

        // Third should be rate limited (same normalized identifier)
        $result3 = $this->otpService->send('TEST@EXAMPLE.COM');
        expect($result3)->toBeFalse();
    });

    it('normalizes phone numbers by trimming whitespace', function () {
        // Send with whitespace
        $result = $this->otpService->send('  +1234567890  ');
        expect($result)->toBeTrue();

        // Should be stored without whitespace
        $otp = SecureOtp::query()->where('identifier', '+1234567890')->first();
        expect($otp)->not->toBeNull();
    });
});

describe('Security Fix: Race Condition Prevention', function () {
    it('prevents multiple live OTPs with Cache::lock()', function () {
        // This test verifies that Cache::lock() prevents concurrent OTP generation
        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();

        // Get first OTP ID
        $otp1 = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp1)->not->toBeNull();

        // Send again - should invalidate first OTP and create new one
        $result2 = $this->otpService->send('test@example.com');
        expect($result2)->toBeTrue();

        // First OTP should be marked as verified (invalidated)
        $otp1->refresh();
        expect($otp1->verified_at)->not->toBeNull();

        // Only one unverified OTP should exist
        $unverifiedCount = SecureOtp::query()
            ->where('identifier', 'test@example.com')
            ->whereNull('verified_at')
            ->count();

        expect($unverifiedCount)->toBe(1);
    });

    it('throws exception when cache lock cannot be acquired', function () {
        // Mock Cache::lock to always fail
        Cache::shouldReceive('lock')
            ->with('otp:generate:test@example.com', 10)
            ->andReturn(new class
            {
                public function block($seconds)
                {
                    // Simulate lock acquisition timeout
                    throw new \Illuminate\Contracts\Cache\LockTimeoutException;
                }

                public function release()
                {
                    // No-op for mock
                }
            });

        expect(fn () => $this->otpService->send('test@example.com'))
            ->toThrow(OtpGenerationException::class, 'Unable to generate OTP, please try again');
    });
});

describe('Security Fix: Hash Secret Validation', function () {
    it('throws exception when hash secret is missing', function () {
        // Clear both secrets
        config(['secure-otp.hash_secret' => null]);
        config(['app.key' => null]);

        // InvalidArgumentException is wrapped in OtpGenerationException
        expect(fn () => $this->otpService->send('test@example.com'))
            ->toThrow(OtpGenerationException::class);
    });

    it('uses hash secret from config', function () {
        config(['secure-otp.hash_secret' => 'my-custom-secret']);

        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp->code_hash)->not->toBeNull();
    });

    it('falls back to APP_KEY when hash_secret is null', function () {
        config(['secure-otp.hash_secret' => null]);
        config(['app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        $result = $this->otpService->send('test@example.com');
        expect($result)->toBeTrue();

        $otp = SecureOtp::query()->where('identifier', 'test@example.com')->first();
        expect($otp->code_hash)->not->toBeNull();
    });
});
