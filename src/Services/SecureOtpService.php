<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Services;

use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;
use Biponix\SecureOtp\Models\SecureOtp;
use Biponix\SecureOtp\Notifications\OtpNotification;
use Biponix\SecureOtp\Support\OnDemandNotifiable;
use Exception;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;

/**
 * Production-Grade OTP Service
 *
 * Features:
 * - Multi-channel delivery (SMS, Email, WhatsApp, Telegram)
 * - Secure hash storage (timing-attack resistant)
 * - Multi-layer rate limiting (identifier + IP)
 * - Replay attack prevention
 * - Race condition protection (database transactions with locks)
 * - Detailed security logging
 * - Generic responses (prevents enumeration attacks)
 */
final class SecureOtpService
{
    /**
     * Generate OTP without sending (for custom delivery)
     *
     * @param  string  $identifier  Email address or phone number
     * @return string|null OTP code, or null if rate limited
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws OtpGenerationException If OTP generation fails
     */
    public function generate(string $identifier): ?string
    {
        // Normalize identifier (lowercase emails, trim whitespace)
        $identifier = $this->normalizeIdentifier($identifier);

        // Validate identifier format
        if (! $this->isValidIdentifier($identifier)) {
            $this->logSecurityEvent('invalid_identifier', $identifier);
            throw new InvalidIdentifierException;
        }

        // Check rate limits (multi-layer protection)
        $rateLimitResult = $this->checkRateLimits($identifier);
        if (! $rateLimitResult['allowed']) {
            $this->logSecurityEvent('rate_limit_exceeded', $identifier, $rateLimitResult);

            return null; // Rate limited - soft failure
        }

        try {
            // Generate and store OTP (atomic transaction)
            [$otpId, $code] = $this->generateAndStoreOtp($identifier);

            // Log success
            if (config('secure-otp.enable_logging')) {
                Log::info('OTP generated successfully (without sending)', [
                    'identifier' => $this->maskIdentifier($identifier),
                    'otp_id' => $otpId,
                    'ip' => $this->getIpAddress(),
                ]);
            }

            return $code;
        } catch (OtpGenerationException $e) {
            throw $e;
        } catch (Exception $e) {
            Log::error('OTP generation failed', [
                'identifier' => $this->maskIdentifier($identifier),
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new OtpGenerationException('Failed to generate OTP', $e);
        }
    }

    /**
     * Send OTP to identifier (email, phone number) - queued
     *
     * @param  string  $identifier  Email address or phone number
     * @return bool True if sent, false if rate limited
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws OtpGenerationException If OTP generation/sending fails
     */
    public function send(string $identifier): bool
    {
        return $this->sendInternal(
            $identifier,
            fn (OnDemandNotifiable $notifiable, Notification $notification) => $notifiable->notify($notification),
            'queued'
        );
    }

    /**
     * Send OTP synchronously (blocks until sent)
     *
     * @param  string  $identifier  Email address or phone number
     * @return bool True if sent, false if rate limited
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws OtpGenerationException If OTP generation/sending fails
     */
    public function sendNow(string $identifier): bool
    {
        return $this->sendInternal(
            $identifier,
            fn (OnDemandNotifiable $notifiable, Notification $notification) => $notifiable->notifyNow($notification),
            'synchronously'
        );
    }

    /**
     * Internal method to send OTP with custom notification strategy
     *
     * @param  string  $identifier  Email address or phone number
     * @param  callable  $sendStrategy  Function to send notification
     * @param  string  $logContext  Context for logging (e.g., 'queued', 'synchronously')
     * @return bool True if sent, false if rate limited
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws OtpGenerationException If OTP generation/sending fails
     */
    private function sendInternal(string $identifier, callable $sendStrategy, string $logContext): bool
    {
        $identifier = $this->normalizeIdentifier($identifier);

        // Generate OTP (already normalized, validation happens inside)
        $code = $this->generate($identifier);

        if ($code === null) {
            return false; // Rate limited
        }

        try {
            $notifiable = new OnDemandNotifiable($identifier);

            $notificationClass = config('secure-otp.notification_class', OtpNotification::class);

            if (! is_subclass_of($notificationClass, Notification::class)) {
                throw new InvalidArgumentException(
                    'Notification class must extend Illuminate\Notifications\Notification'
                );
            }

            // Send notification using provided strategy
            $sendStrategy($notifiable, new $notificationClass($code));

            // Log success
            if (config('secure-otp.enable_logging')) {
                Log::info("OTP sent successfully ({$logContext})", [
                    'identifier' => $this->maskIdentifier($identifier),
                    'ip' => $this->getIpAddress(),
                ]);
            }

            return true;
        } catch (Exception $e) {
            Log::error("OTP send failed ({$logContext})", [
                'identifier' => $this->maskIdentifier($identifier),
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw new OtpGenerationException('Failed to send OTP', $e);
        }
    }

    /**
     * Verify OTP code
     *
     * Security: Rate limits verification attempts to prevent brute force attacks.
     * Even though each OTP has max_attempts limit, we also limit verification calls
     * to prevent attackers from rapidly trying different codes.
     *
     * @param  string  $identifier  Phone number or email address
     * @param  string  $code  6-digit OTP code
     * @return bool True if verified successfully, false otherwise
     */
    public function verify(string $identifier, string $code): bool
    {
        // Normalize identifier (must match how it was stored)
        $identifier = $this->normalizeIdentifier($identifier);

        // Validate code format
        $codeLength = config('secure-otp.length', 6);
        if (! preg_match("/^\d{{$codeLength}}$/", $code)) {
            $this->logSecurityEvent('invalid_code_format', $identifier);

            return false;
        }

        // Rate limit verification attempts (prevent brute force)
        $rateLimitResult = $this->checkRateLimits($identifier, 'verify');
        if (! $rateLimitResult['allowed']) {
            $this->logSecurityEvent('verification_rate_limit_exceeded', $identifier, $rateLimitResult);

            return false;
        }

        try {
            return DB::transaction(function () use ($identifier, $code): bool {
                // Find latest valid OTP (with row lock to prevent race)
                $otp = SecureOtp::forIdentifier($identifier)
                    ->valid()
                    ->orderBy('created_at', 'desc')
                    ->lockForUpdate()
                    ->first();

                if (! $otp) {
                    $this->logSecurityEvent('otp_not_found', $identifier, ['reason' => 'not_found_or_expired']);

                    return false;
                }

                // Check max attempts
                if ($otp->hasMaxAttemptsReached()) {
                    $this->logSecurityEvent('max_attempts_exceeded', $identifier, ['otp_id' => $otp->id]);

                    return false;
                }

                // Verify code (timing-safe comparison with HMAC)
                $providedHash = $this->hashCode($code);

                if (! hash_equals($otp->code_hash, $providedHash)) {
                    // Increment attempts
                    $otp->incrementAttempts();

                    $this->logSecurityEvent('invalid_code', $identifier, [
                        'otp_id' => $otp->id,
                        'attempts' => $otp->attempts,
                    ]);

                    return false;
                }

                // Success! Mark as verified
                $otp->markAsVerified();

                if (config('secure-otp.enable_logging')) {
                    Log::info('OTP verified successfully', [
                        'identifier' => $this->maskIdentifier($identifier),
                        'otp_id' => $otp->id,
                        'ip' => $this->getIpAddress(),
                    ]);
                }

                return true;
            });
        } catch (Exception $e) {
            Log::error('OTP verification error', [
                'identifier' => $this->maskIdentifier($identifier),
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Generate OTP and store in database (atomic transaction with distributed lock)
     *
     * Security: Cache lock prevents race condition where concurrent sends
     * could create multiple live OTPs for the same identifier.
     *
     * @return array [uuid, code]
     *
     * @throws OtpGenerationException If unable to acquire lock
     */
    protected function generateAndStoreOtp(string $identifier): array
    {
        // Acquire distributed lock to serialize OTP generation for this identifier
        $lock = Cache::lock("otp:generate:{$identifier}", 10);

        try {
            // Wait up to 3 seconds to acquire lock
            try {
                $lock->block(3);
            } catch (LockTimeoutException) {
                throw new OtpGenerationException('Unable to generate OTP, please try again');
            }

            return DB::transaction(function () use ($identifier) {
                // Invalidate all previous OTPs for this identifier (atomic)
                SecureOtp::forIdentifier($identifier)
                    ->whereNull('verified_at')
                    ->lockForUpdate()
                    ->update(['verified_at' => now()]);

                // Generate new OTP
                $code = $this->generateCode();
                $expiryMinutes = config('secure-otp.expiry_minutes', 5);

                $otp = SecureOtp::create([
                    'identifier' => $identifier,
                    'code_hash' => $this->hashCode($code), // Use HMAC for security
                    'attempts' => 0,
                    'expires_at' => now()->addMinutes($expiryMinutes),
                    'created_at' => now(),
                ]);

                return [$otp->id, $code];
            });
        } finally {
            // Always release lock
            optional($lock)->release();
        }
    }

    /**
     * Check multi-layer rate limits with context-aware configuration
     *
     * Supports context-specific rate limits (e.g., different limits for generate vs verify).
     * Falls back to shared config if context-specific config is not set.
     *
     * @param  string  $identifier  Email or phone number
     * @param  string  $context  Operation context: 'generate' or 'verify'
     * @return array{allowed: bool, key?: string, available_in?: int}
     */
    protected function checkRateLimits(string $identifier, string $context = 'generate'): array
    {
        $ip = $this->getIpAddress();
        $prefix = config('secure-otp.rate_limits.prefix', 'secure-otp');

        // Try context-specific config first, fall back to shared config
        // Examples:
        //   - verify_per_identifier (specific) OR per_identifier (shared)
        //   - verify_per_ip (specific) OR per_ip (shared)
        $identifierConfig = config("secure-otp.rate_limits.{$context}_per_identifier")
            ?? config('secure-otp.rate_limits.per_identifier');

        $ipConfig = config("secure-otp.rate_limits.{$context}_per_ip")
            ?? config('secure-otp.rate_limits.per_ip');

        // Build rate limit keys with context suffix
        // Examples:
        //   - secure-otp:generate:identifier:user@example.com
        //   - secure-otp:verify:identifier:user@example.com
        $limits = [
            "{$prefix}:{$context}:identifier:{$identifier}" => $identifierConfig,
        ];

        // Only apply IP rate limiting in HTTP contexts (not console/queue)
        if ($ip !== null) {
            $limits["{$prefix}:{$context}:ip:{$ip}"] = $ipConfig;
        }

        foreach ($limits as $key => $config) {
            // Skip if config is not an array (disabled axis)
            if (! is_array($config)) {
                continue;
            }

            $maxAttempts = $config['max_attempts'];
            $decaySeconds = $config['decay_seconds'];

            if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
                return [
                    'allowed' => false,
                    'key' => $key,
                    'available_in' => RateLimiter::availableIn($key),
                ];
            }

            RateLimiter::hit($key, $decaySeconds);
        }

        return ['allowed' => true];
    }

    /**
     * Normalize identifier to prevent bypass via case/whitespace variations
     *
     * Security: Ensures send('User@Example.COM') and verify('user@example.com')
     * reference the same OTP and rate limit slot.
     */
    protected function normalizeIdentifier(string $identifier): string
    {
        $identifier = trim($identifier);

        // Email: lowercase to prevent case-based bypass
        // Example: User@Example.COM -> user@example.com
        if (str_contains($identifier, '@')) {
            return strtolower($identifier);
        }

        // Phone: E.164 format is already case-insensitive, just trim
        return $identifier;
    }

    /**
     * Validate identifier format
     */
    protected function isValidIdentifier(string $identifier): bool
    {
        // Prevent DoS via huge identifiers
        if (strlen($identifier) > 255) {
            return false;
        }

        // Phone: international format (E.164)
        if (preg_match('/^\+?[1-9]\d{1,14}$/', $identifier)) {
            return true;
        }

        // Email: basic validation
        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            return true;
        }

        return false;
    }

    /**
     * Generate cryptographically secure OTP code
     */
    protected function generateCode(): string
    {
        $length = config('secure-otp.length', 6);
        $max = (int) str_repeat('9', $length);

        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }

    /**
     * Mask identifier for logging (privacy)
     */
    protected function maskIdentifier(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            // Email: show first 2 chars and domain
            [$local, $domain] = explode('@', $identifier);

            return substr($local, 0, 2).'***@'.$domain;
        }

        // Phone: show last 4 digits
        return '***'.substr($identifier, -4);
    }

    /**
     * Log security events
     */
    protected function logSecurityEvent(string $event, string $identifier, array $context = []): void
    {
        if (! config('secure-otp.enable_logging')) {
            return;
        }

        Log::warning("OTP security event: {$event}", array_merge([
            'identifier' => $this->maskIdentifier($identifier),
            'ip' => $this->getIpAddress(),
            'user_agent' => $this->getUserAgent(),
        ], $context));
    }

    /**
     * Cleanup expired OTPs (call from scheduled task)
     */
    public function cleanupExpired(): int
    {
        $hours = config('secure-otp.cleanup_after_hours', 24);

        return SecureOtp::where('created_at', '<', now()->subHours($hours))
            ->delete();
    }

    /**
     * Get IP address safely (works in HTTP, queue, console contexts)
     */
    protected function getIpAddress(): ?string
    {
        if (! app()->has('request')) {
            return null;
        }

        return app('request')->ip();
    }

    /**
     * Get user agent safely (works in HTTP, queue, console contexts)
     */
    protected function getUserAgent(): ?string
    {
        if (! app()->has('request')) {
            return null;
        }

        return app('request')->userAgent();
    }

    /**
     * Hash OTP code securely using HMAC to prevent rainbow table attacks
     *
     * @throws InvalidArgumentException If hash secret is not configured
     */
    protected function hashCode(string $code): string
    {
        $algorithm = config('secure-otp.hash_algorithm', 'sha256');
        $secret = config('secure-otp.hash_secret') ?? config('app.key');

        // Fail fast if secret is missing (prevents weak hashes)
        if (empty($secret)) {
            throw new InvalidArgumentException(
                'Hash secret is required. Set OTP_HASH_SECRET or APP_KEY in your .env file.'
            );
        }

        // Use HMAC with secret to prevent rainbow table attacks
        // Even if attacker gets DB access, they can't reverse 6-digit codes without secret
        return hash_hmac($algorithm, $code, $secret);
    }
}
