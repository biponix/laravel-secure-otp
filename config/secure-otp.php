<?php

use Biponix\SecureOtp\Notifications\OtpNotification;

return [

    /*
    |--------------------------------------------------------------------------
    | OTP Expiry Time
    |--------------------------------------------------------------------------
    |
    | The number of minutes an OTP remains valid after being sent.
    | Industry standard is 5-15 minutes.
    |
    */

    'expiry_minutes' => env('OTP_EXPIRY_MINUTES', 5),

    /*
    |--------------------------------------------------------------------------
    | OTP Code Length
    |--------------------------------------------------------------------------
    |
    | The number of digits in the OTP code.
    | 6 digits is industry standard (provides 1,000,000 combinations).
    |
    */

    'length' => env('OTP_LENGTH', 6),

    /*
    |--------------------------------------------------------------------------
    | Maximum Verification Attempts
    |--------------------------------------------------------------------------
    |
    | Maximum number of times a user can attempt to verify an OTP
    |
    */

    'max_attempts' => env('OTP_MAX_ATTEMPTS', 3),

    /*
    |--------------------------------------------------------------------------
    | Hash Algorithm & Secret
    |--------------------------------------------------------------------------
    |
    | Algorithm used to hash OTP codes before storing in database.
    | SHA-256 is sufficient for short-lived OTPs.
    |
    | IMPORTANT: hash_secret must be set to prevent rainbow table attacks.
    | By default, uses Laravel's APP_KEY.
    |
    | Security: With hash_secret, even if attacker gets database access,
    | they cannot reverse the 6-digit codes without knowing the secret.
    |
    */

    'hash_algorithm' => env('OTP_HASH_ALGORITHM', 'sha256'),
    'hash_secret' => env('OTP_HASH_SECRET', null), // null = use config('app.key')

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limits to prevent abuse.
    | Format: [max_attempts, decay_seconds]
    |
    | Prefix: Customize the cache key prefix for rate limiting.
    | Useful when multiple applications share the same cache store.
    |
    | Context-Specific Limits:
    | You can optionally define different limits for 'generate' vs 'verify':
    | - verify_per_identifier: Overrides per_identifier for verification
    | - verify_per_ip: Overrides per_ip for verification
    | If not set, falls back to the shared per_identifier and per_ip config.
    |
    */

    'rate_limits' => [
        // Cache key prefix (prevent collisions in shared cache)
        'prefix' => env('OTP_RATE_LIMIT_PREFIX', 'secure-otp'),

        // Per phone/email identifier (shared default for generate & verify)
        'per_identifier' => [
            'max_attempts' => env('OTP_RATE_LIMIT_IDENTIFIER', 3),
            'decay_seconds' => env('OTP_RATE_LIMIT_IDENTIFIER_DECAY', 3600), // 1 hour
        ],

        // Per IP address (shared default for generate & verify)
        'per_ip' => [
            'max_attempts' => env('OTP_RATE_LIMIT_IP', 10),
            'decay_seconds' => env('OTP_RATE_LIMIT_IP_DECAY', 3600), // 1 hour
        ],

        // Optional: Override limits specifically for verification (prevent brute force)
        // If not set, falls back to per_identifier above
        'verify_per_identifier' => [
            'max_attempts' => env('OTP_VERIFY_RATE_LIMIT_IDENTIFIER', 5),
            'decay_seconds' => env('OTP_VERIFY_RATE_LIMIT_IDENTIFIER_DECAY', 60), // 1 minute
        ],

        // Optional: Override IP limits specifically for verification
        // If not set, falls back to per_ip above
        'verify_per_ip' => [
            'max_attempts' => env('OTP_VERIFY_RATE_LIMIT_IP', 20),
            'decay_seconds' => env('OTP_VERIFY_RATE_LIMIT_IP_DECAY', 60), // 1 minute
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | OTP Notification Class
    |--------------------------------------------------------------------------
    |
    | The notification class used to send OTP codes.
    | You can replace this with your own custom notification class.
    |
    | Requirements:
    | - Must extend Illuminate\Notifications\Notification
    | - Constructor: __construct(string $code)
    | - Method: via(object $notifiable): array
    | - Implement channel methods you need: toMail(), toSms(), toWhatsapp(), etc.
    |
    | Example:
    |   class MyOtpNotification extends Notification {
    |       public function __construct(public string $code) {}
    |       public function via($notifiable): array { return ['mail']; }
    |       public function toMail($notifiable): MailMessage {
    |           return (new MailMessage)->line("Code: {$this->code}");
    |       }
    |   }
    |
    */

    'notification_class' => env('OTP_NOTIFICATION_CLASS', OtpNotification::class),

    /*
    |--------------------------------------------------------------------------
    | Cleanup
    |--------------------------------------------------------------------------
    |
    | How long to keep OTP records after creation before cleanup.
    | Old records should be deleted periodically to keep table lean.
    |
    */

    'cleanup_after_hours' => env('OTP_CLEANUP_AFTER_HOURS', 24),

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    |
    | Enable detailed logging for debugging and security monitoring.
    | WARNING: Logs may contain sensitive information in development.
    |
    */

    'enable_logging' => env('OTP_ENABLE_LOGGING', true),

];
