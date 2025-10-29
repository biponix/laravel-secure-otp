# Laravel Secure OTP

[![Latest Version on Packagist](https://img.shields.io/packagist/v/biponix/laravel-secure-otp.svg?style=flat-square)](https://packagist.org/packages/biponix/laravel-secure-otp)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/biponix/laravel-secure-otp/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/biponix/laravel-secure-otp/actions/workflows/run-tests.yml)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/biponix/laravel-secure-otp/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/biponix/laravel-secure-otp/actions/workflows/fix-php-code-style-issues.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/biponix/laravel-secure-otp?style=flat-square)](https://packagist.org/packages/biponix/laravel-secure-otp)

A production-ready, secure OTP (One-Time Password) package for Laravel applications. Generate and verify OTP codes via Email, SMS, WhatsApp, or any Laravel notification channel.

## Features

- ✅ **Production-Grade Security**: HMAC-based storage with secret key, timing-attack resistant verification
- ✅ **Multi-Channel Support**: Email, SMS, WhatsApp, Telegram (via Laravel Notifications)
- ✅ **Context-Safe**: Works seamlessly in HTTP, queue workers, and console commands
- ✅ **Context-Aware Rate Limiting**: Separate limits for generation vs verification (brute force protection)
- ✅ **Multi-Layer Protection**: Per-identifier + per-IP rate limiting in HTTP contexts
- ✅ **Attack Prevention**: Replay attack prevention, race condition protection with distributed cache locks
- ✅ **Fully Customizable**: Custom notification classes, configurable expiry, length, attempts
- ✅ **Security Logging**: Detailed audit logs with privacy-preserving PII masking
- ✅ **100% Test Coverage**: 108 comprehensive tests ensuring reliability
- ✅ **Wide Compatibility**: PHP 8.1-8.4, Laravel 10-12

## Installation

You can install the package via composer:

```bash
composer require biponix/laravel-secure-otp
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag="secure-otp-migrations"
php artisan migrate
```

Publish the config file (optional):

```bash
php artisan vendor:publish --tag="secure-otp-config"
```

## Configuration

The config file (`config/secure-otp.php`) allows you to customize:

```php
return [
    // OTP expiry in minutes (default: 5)
    'expiry_minutes' => env('OTP_EXPIRY_MINUTES', 5),

    // OTP code length (default: 6 digits)
    'length' => env('OTP_LENGTH', 6),

    // Maximum verification attempts (default: 3)
    'max_attempts' => env('OTP_MAX_ATTEMPTS', 3),

    // Hash algorithm and secret for HMAC (prevents rainbow table attacks)
    'hash_algorithm' => env('OTP_HASH_ALGORITHM', 'sha256'),
    'hash_secret' => env('OTP_HASH_SECRET', null), // Falls back to app.key if null

    // Context-aware rate limiting (separate limits for generation vs verification)
    'rate_limits' => [
        // Cache key prefix (prevents collisions in shared cache)
        'prefix' => env('OTP_RATE_LIMIT_PREFIX', 'secure-otp'),

        // Shared defaults (used for both generate and verify if context-specific not set)
        'per_identifier' => [
            'max_attempts' => env('OTP_RATE_LIMIT_IDENTIFIER', 3),
            'decay_seconds' => env('OTP_RATE_LIMIT_IDENTIFIER_DECAY', 3600), // 1 hour
        ],
        'per_ip' => [
            'max_attempts' => env('OTP_RATE_LIMIT_IP', 10),
            'decay_seconds' => env('OTP_RATE_LIMIT_IP_DECAY', 3600), // 1 hour
        ],

        // Optional: Override limits specifically for verification (prevent brute force)
        'verify_per_identifier' => [
            'max_attempts' => env('OTP_VERIFY_RATE_LIMIT_IDENTIFIER', 5),
            'decay_seconds' => env('OTP_VERIFY_RATE_LIMIT_IDENTIFIER_DECAY', 60), // 1 minute
        ],
        'verify_per_ip' => [
            'max_attempts' => env('OTP_VERIFY_RATE_LIMIT_IP', 20),
            'decay_seconds' => env('OTP_VERIFY_RATE_LIMIT_IP_DECAY', 60), // 1 minute
        ],
    ],

    // Custom notification class
    'notification_class' => env('OTP_NOTIFICATION_CLASS', \Biponix\SecureOtp\Notifications\OtpNotification::class),

    // Cleanup after hours (default: 24)
    'cleanup_after_hours' => env('OTP_CLEANUP_AFTER_HOURS', 24),

    // Enable security logging (default: true)
    'enable_logging' => env('OTP_ENABLE_LOGGING', true),
];
```

## Usage

### Basic Usage

```php
use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;
use Biponix\SecureOtp\Services\SecureOtpService;

class AuthController extends Controller
{
    public function sendOtp(Request $request, SecureOtpService $otp)
    {
        try {
            $sent = $otp->send($request->email); // Returns bool

            if ($sent) {
                return response()->json([
                    'message' => 'If this is a valid email, you will receive a code.'
                ]);
            }

            // Rate limited
            return response()->json([
                'message' => 'Too many requests. Please try again later.'
            ], 429);

        } catch (InvalidIdentifierException $e) {
            return response()->json(['error' => 'Invalid email address'], 422);
        } catch (OtpGenerationException $e) {
            return response()->json(['error' => 'Failed to send OTP'], 500);
        }
    }

    public function verifyOtp(Request $request, SecureOtpService $otp)
    {
        $verified = $otp->verify($request->email, $request->code); // Returns bool

        if ($verified) {
            // OTP verified successfully
            $user = User::where('email', $request->email)->firstOrFail();
            auth()->login($user);

            return response()->json(['message' => 'Login successful']);
        }

        return response()->json(['error' => 'Invalid or expired code'], 422);
    }
}
```

### Using with Dependency Injection

```php
use Biponix\SecureOtp\Services\SecureOtpService;

public function __construct(
    private SecureOtpService $otp
) {}

public function sendCode(string $identifier): bool
{
    return $this->otp->send($identifier);
}
```

### Generate Without Sending (Custom Delivery)

```php
use Biponix\SecureOtp\Services\SecureOtpService;

public function customDelivery(SecureOtpService $otp)
{
    // Generate OTP without sending (returns string|null)
    $code = $otp->generate('user@example.com');

    if ($code === null) {
        // Rate limited
        return;
    }

    // Deliver via your custom method
    $this->sendViaSms($code);
}
```

### Send Synchronously (Block Until Sent)

```php
// Default: queued (non-blocking)
$otp->send('user@example.com');

// Force synchronous sending (blocks until sent)
$otp->sendNow('user@example.com');
```

### Using the Facade (Optional)

```php
use Biponix\SecureOtp\Facades\SecureOtp;

// Send OTP (returns bool)
$sent = SecureOtp::send('user@example.com');

// Verify OTP (returns bool)
$verified = SecureOtp::verify('user@example.com', '123456');

// Generate without sending (returns string|null)
$code = SecureOtp::generate('user@example.com');

// Send synchronously
$sent = SecureOtp::sendNow('user@example.com');
```

### Custom Notification Channels

Create your own notification class to use SMS, WhatsApp, or other channels:

```php
namespace App\Notifications;

use Illuminate\Notifications\Notification;

class SmsOtpNotification extends Notification
{
    public function __construct(public string $code) {}

    public function via($notifiable): array
    {
        return ['twilio']; // or 'vonage', 'whatsapp', etc.
    }

    public function toTwilio($notifiable)
    {
        return (new TwilioSmsMessage())
            ->content("Your verification code is: {$this->code}");
    }
}
```

Update your `.env`:

```env
OTP_NOTIFICATION_CLASS="App\Notifications\SmsOtpNotification"
```

### Cleanup Expired OTPs

The package requires scheduled cleanup to remove expired OTP records from the database.

**Step 1: Add to Laravel Scheduler**

In Laravel 11+, add to `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('secure-otp:clean --force')
    ->daily()
    ->withoutOverlapping()
    ->onOneServer();
```

Or in `app/Console/Kernel.php` (Laravel 10 and below):

```php
protected function schedule(Schedule $schedule)
{
    $schedule->command('secure-otp:clean --force')
             ->daily()
             ->withoutOverlapping()
             ->onOneServer();
}
```

**Step 2: Ensure Cron is Running**

Make sure your server has the Laravel scheduler cron job configured:

```bash
* * * * * cd /path-to-your-project && php artisan schedule:run >> /dev/null 2>&1
```

**Manual Cleanup (Optional)**

```bash
# In development (prompts for confirmation)
php artisan secure-otp:clean

# In production (bypasses confirmation)
php artisan secure-otp:clean --force
```

**Programmatic Cleanup (Advanced)**

```php
use Biponix\SecureOtp\Services\SecureOtpService;

$deleted = app(SecureOtpService::class)->cleanupExpired();
// Returns the number of deleted records
```

## Security Features

### 1. HMAC-Based Storage (Rainbow Table Protection)
OTP codes are hashed using **HMAC-SHA256 with a secret key** before storage. This prevents rainbow table attacks even if the database is compromised. Plain codes are never saved.

```php
// Configure in .env
OTP_HASH_SECRET=your-secret-key  // Falls back to APP_KEY if not set
```

### 2. Timing-Safe Comparison
Uses `hash_equals()` to prevent timing attacks during verification.

### 3. Context-Aware Rate Limiting (Brute Force Protection)

**Separate rate limits for generation vs verification** to balance security and user experience:

#### Generation (Sending OTP)
- **Per Identifier**: 3 attempts/hour (prevents spam to a user)
- **Per IP**: 10 attempts/hour (prevents mass spamming from one IP)

#### Verification (Checking OTP)
- **Per Identifier**: 5 attempts/minute (more lenient, user may typo)
- **Per IP**: 20 attempts/minute (prevents distributed brute force across multiple accounts)

**Key Features:**
- **Smart Detection**: IP rate limiting automatically skipped in queue/console contexts
- **Flexible Configuration**: Supports context-specific overrides (`verify_per_identifier`) or falls back to shared config
- **Cache Key Isolation**: Uses context-aware keys (e.g., `secure-otp:verify:identifier:user@example.com`)
- **Per-Axis Control**: Each rate limiting axis can be disabled independently by setting to `null` or `false`

### 4. Generic Responses
Returns boolean values instead of detailed error messages to prevent enumeration attacks.

### 5. Race Condition Protection
Uses distributed cache locks (`Cache::lock()`) combined with database transactions and row-level locks (`lockForUpdate()`) to serialize OTP generation and ensure only one valid OTP exists per identifier at any time. Lock timeouts (3 seconds) provide friendly error messages under high concurrency.

### 6. Replay Attack Prevention
Previous OTPs are automatically invalidated when a new one is generated.

### 7. Attempt Limiting
Maximum verification attempts per OTP (default: 3) to prevent brute force attacks.

### 8. Security Logging with Privacy
Logs all security events (invalid codes, rate limits, etc.) with PII masking:
- Emails: `te***@example.com`
- Phones: `***7890`

## API Reference

### `generate(string $identifier): ?string`

Generates an OTP code without sending it (for custom delivery methods).

**Parameters:**
- `$identifier` (string): Email address or phone number (E.164 format)

**Returns:**
- `string`: The generated OTP code
- `null`: If rate limited

**Throws:**
- `InvalidIdentifierException`: If the identifier format is invalid
- `OtpGenerationException`: If OTP generation fails

---

### `send(string $identifier): bool`

Generates and queues an OTP notification to the given identifier (non-blocking).

**Parameters:**
- `$identifier` (string): Email address or phone number (E.164 format)

**Returns:**
- `true`: OTP sent successfully
- `false`: Rate limited

**Throws:**
- `InvalidIdentifierException`: If the identifier format is invalid
- `OtpGenerationException`: If OTP generation/sending fails

---

### `sendNow(string $identifier): bool`

Generates and sends an OTP synchronously to the given identifier (blocks until sent).

**Parameters:**
- `$identifier` (string): Email address or phone number (E.164 format)

**Returns:**
- `true`: OTP sent successfully
- `false`: Rate limited

**Throws:**
- `InvalidIdentifierException`: If the identifier format is invalid
- `OtpGenerationException`: If OTP generation/sending fails

---

### `verify(string $identifier, string $code): bool`

Verifies an OTP code for the given identifier.

**Parameters:**
- `$identifier` (string): Email address or phone number
- `$code` (string): The OTP code to verify (6 digits by default)

**Returns:**
- `true`: OTP verified successfully
- `false`: Verification failed (invalid, expired, max attempts exceeded, etc.)

---

### `cleanupExpired(): int`

Deletes expired OTP records older than configured hours.

**Returns:** Number of deleted records

## Testing

The package includes comprehensive tests:

```bash
composer test
```

Run tests with coverage (requires PCOV or Xdebug):

```bash
composer test-coverage
```

The package maintains **100% code coverage** with 112 comprehensive tests covering all security features, edge cases, and error scenarios.

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

If you discover a security vulnerability, please send an email to [ashiquzzaman33@gmail.com](mailto:ashiquzzaman33@gmail.com). All security vulnerabilities will be promptly addressed.

## Credits

- [Md Ashiquzzaman](https://github.com/ashiquzzaman33)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
