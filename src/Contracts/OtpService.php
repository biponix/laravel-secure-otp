<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Contracts;

use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;
use Biponix\SecureOtp\Exceptions\RateLimitExceededException;

/**
 * OTP Service Contract
 *
 * This interface defines the contract for OTP generation, sending, and verification.
 * Implementing classes must provide secure OTP handling with rate limiting and validation.
 *
 * @see \Biponix\SecureOtp\Services\SecureOtpService
 */
interface OtpService
{
    /**
     * Generate OTP without sending (for custom delivery)
     *
     * @param  string  $identifier  Email, phone, username, or any identifier
     * @param  string|null  $type  Identifier type (e.g., 'email', 'sms', 'username')
     * @return string OTP code
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws RateLimitExceededException If rate limit is exceeded
     * @throws OtpGenerationException If OTP generation fails
     */
    public function generate(string $identifier, ?string $type = null): string;

    /**
     * Send OTP to identifier (email, phone number) - queued
     *
     * @param  string  $identifier  Email, phone, username, or any identifier
     * @param  string|null  $type  Identifier type (e.g., 'email', 'sms', 'username')
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws RateLimitExceededException If rate limit is exceeded
     * @throws OtpGenerationException If OTP generation/sending fails
     */
    public function send(string $identifier, ?string $type = null): void;

    /**
     * Send OTP synchronously (blocks until sent)
     *
     * @param  string  $identifier  Email, phone, username, or any identifier
     * @param  string|null  $type  Identifier type (e.g., 'email', 'sms', 'username')
     *
     * @throws InvalidIdentifierException If identifier format is invalid
     * @throws RateLimitExceededException If rate limit is exceeded
     * @throws OtpGenerationException If OTP generation/sending fails
     */
    public function sendNow(string $identifier, ?string $type = null): void;

    /**
     * Verify OTP code
     *
     * Security: Rate limits verification attempts to prevent brute force attacks.
     * Even though each OTP has max_attempts limit, we also limit verification calls
     * to prevent attackers from rapidly trying different codes.
     *
     * @param  string  $identifier  Phone number, email address, username, or any identifier
     * @param  string  $code  OTP code (length based on config)
     * @param  string|null  $type  Identifier type (must match the type used in send())
     * @return bool True if verified successfully, false otherwise
     */
    public function verify(string $identifier, string $code, ?string $type = null): bool;

    /**
     * Cleanup expired OTPs (call from scheduled task)
     *
     * @return int Number of deleted records
     */
    public function cleanupExpired(): int;

    /**
     * Register a custom identifier type
     *
     * Example:
     * ```php
     * SecureOtpService::addType('sms', new BangladeshSmsType());
     * SecureOtp::send('01700000000', 'sms'); // Uses BangladeshSmsType
     * ```
     *
     * @param  string  $name  Type name (e.g., 'sms', 'email', 'username')
     * @param  OtpIdentifierType  $type  Type implementation
     */
    public static function addType(string $name, OtpIdentifierType $type): void;

    /**
     * Get registered identifier type
     *
     * @param  string  $name  Type name
     * @return OtpIdentifierType|null Type implementation or null if not registered
     */
    public static function getType(string $name): ?OtpIdentifierType;

    /**
     * Check if a type is registered
     *
     * @param  string  $name  Type name
     * @return bool True if type is registered, false otherwise
     */
    public static function hasType(string $name): bool;
}
