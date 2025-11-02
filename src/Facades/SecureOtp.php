<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Facades;

use Biponix\SecureOtp\Contracts\OtpIdentifierType;
use Illuminate\Support\Facades\Facade;

/**
 * @see \Biponix\SecureOtp\Contracts\OtpService
 * @see \Biponix\SecureOtp\Services\SecureOtpService
 *
 * @method static string generate(string $identifier, ?string $type = null)
 * @method static void send(string $identifier, ?string $type = null)
 * @method static void sendNow(string $identifier, ?string $type = null)
 * @method static bool verify(string $identifier, string $code, ?string $type = null)
 * @method static int cleanupExpired()
 * @method static void addType(string $name, OtpIdentifierType $type)
 * @method static OtpIdentifierType|null getType(string $name)
 * @method static bool hasType(string $name)
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
