<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Contracts;

/**
 * OTP Identifier Type Contract
 *
 * Defines how identifiers are normalized and validated for specific types
 * (email, phone, username, user_id, etc.)
 *
 * Example:
 * ```php
 * class SmsIdentifierType extends OtpIdentifierType
 * {
 *     public function normalize(string $value): string
 *     {
 *         // Convert Bangladesh local format to E.164
 *         $value = preg_replace('/[\s\-\(\)]/', '', $value);
 *         if (preg_match('/^0\d{10}$/', $value)) {
 *             return '+880' . substr($value, 1);
 *         }
 *         return $value;
 *     }
 *
 *     public function validate(string $value): bool
 *     {
 *         return preg_match('/^\+880\d{10}$/', $value);
 *     }
 * }
 * ```
 */
abstract class OtpIdentifierType
{
    /**
     * Normalize the identifier value
     *
     * Called before validation. Use this to convert identifiers to a
     * standard format (e.g., lowercase emails, add country code to phones).
     *
     * @param  string  $value  Raw identifier value
     * @return string Normalized identifier
     */
    public function normalize(string $value): string
    {
        return trim($value);
    }

    /**
     * Validate the normalized identifier
     *
     * Called after normalization. Return true if the identifier is valid,
     * false otherwise.
     *
     * @param  string  $value  Normalized identifier value
     * @return bool True if valid, false otherwise
     */
    abstract public function validate(string $value): bool;
}
