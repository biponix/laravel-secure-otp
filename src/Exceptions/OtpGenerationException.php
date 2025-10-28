<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Exceptions;

use Exception;
use Throwable;

class OtpGenerationException extends Exception
{
    public function __construct(string $message = 'Failed to generate OTP', ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
