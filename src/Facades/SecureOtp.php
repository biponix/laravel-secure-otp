<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Biponix\SecureOtp\Services\SecureOtpService
 *
 * @codeCoverageIgnore
 */
class SecureOtp extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'secure-otp';
    }
}
