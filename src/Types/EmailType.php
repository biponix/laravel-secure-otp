<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Types;

use Biponix\SecureOtp\Contracts\OtpIdentifierType;

/**
 * Email Identifier Type
 *
 * Normalizes and validates email addresses.
 * Provided by the package as a default implementation.
 */
class EmailType extends OtpIdentifierType
{
    /**
     * Normalize email address (lowercase + trim)
     */
    public function normalize(string $value): string
    {
        return strtolower(trim($value));
    }

    /**
     * Validate email address format
     */
    public function validate(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
}
