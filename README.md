# Laravel Secure OTP

[![Latest Version on Packagist](https://img.shields.io/packagist/v/biponix/laravel-secure-otp.svg?style=flat-square)](https://packagist.org/packages/biponix/laravel-secure-otp)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/biponix/laravel-secure-otp/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/biponix/laravel-secure-otp/actions/workflows/run-tests.yml)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/biponix/laravel-secure-otp/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/biponix/laravel-secure-otp/actions/workflows/fix-php-code-style-issues.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/biponix/laravel-secure-otp?style=flat-square)](https://packagist.org/packages/biponix/laravel-secure-otp)

A production-ready, secure OTP (One-Time Password) package for Laravel applications. Generate and verify OTP codes via Email, SMS, WhatsApp, or any Laravel notification channel.

## Features

- ✅ **Production-Grade Security**: HMAC-based storage with secret key, timing-attack resistant verification
- ✅ **Multi-Channel Support**: Email, SMS, WhatsApp, Telegram (via Laravel Notifications)
- ✅ **Pluggable Identifier Types**: Extensible validation/normalization for emails, phones, usernames, user IDs, etc.
- ✅ **Context-Safe**: Works seamlessly in HTTP, queue workers, and console commands
- ✅ **Context-Aware Rate Limiting**: Separate limits for generation vs verification (brute force protection)
- ✅ **Multi-Layer Protection**: Per-identifier + per-IP rate limiting in HTTP contexts
- ✅ **Attack Prevention**: Replay attack prevention, race condition protection with distributed cache locks
- ✅ **Fully Customizable**: Custom notification classes, configurable expiry, length, attempts
- ✅ **Security Logging**: Detailed audit logs with privacy-preserving PII masking
- ✅ **100% Test Coverage**: 104 comprehensive tests ensuring reliability
- ✅ **Wide Compatibility**: PHP 8.1-8.4, Laravel 10-12

## Installation

You can install the package via composer:

```bash
composer require biponix/laravel-secure-otp
```

Run the migrations:

```bash
php artisan migrate
```

The migrations will run automatically from the package. If you need to customize the migration, you can publish it first:

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

### Quick Start

**Without Type Validation (Pass-through Mode)**

```php
use Biponix\SecureOtp\Services\SecureOtpService;

$otp = app(SecureOtpService::class);

// Send OTP to any identifier (no validation)
$otp->send('01700000000');        // Bangladesh phone
$otp->send('user@example.com');   // Email
$otp->send('username123');        // Username
$otp->send('12345');              // User ID

// Verify OTP
$verified = $otp->verify('01700000000', '123456');
```

**With Type Validation** (Recommended for production)

```php
use Biponix\SecureOtp\Services\SecureOtpService;
use Biponix\SecureOtp\Types\EmailType;

// Register identifier types in AppServiceProvider::boot()
SecureOtpService::addType('email', new EmailType());

// Now use with type parameter
$otp->send('user@example.com', 'email');     // ✅ Validated & normalized
$otp->verify('user@example.com', '123456', 'email');
```

### Basic Usage Example

```php
use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\RateLimitExceededException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;
use Biponix\SecureOtp\Services\SecureOtpService;

class AuthController extends Controller
{
    public function sendOtp(Request $request, SecureOtpService $otp)
    {
        try {
            // Send OTP (throws on error)
            $otp->send($request->email, 'email');

            return response()->json([
                'message' => 'OTP sent successfully'
            ]);

        } catch (RateLimitExceededException $e) {
            // Rate limit exceeded
            return response()->json([
                'error' => 'Too many requests',
                'retry_after' => $e->getRetryAfter(),
            ], 429);

        } catch (InvalidIdentifierException $e) {
            return response()->json(['error' => 'Invalid email address'], 400);

        } catch (OtpGenerationException $e) {
            return response()->json(['error' => 'Failed to send OTP'], 500);
        }
    }

    public function verifyOtp(Request $request, SecureOtpService $otp)
    {
        // verify() returns bool (doesn't expose why it failed for security)
        $verified = $otp->verify($request->email, $request->code, 'email');

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

public function sendCode(string $identifier): void
{
    // Throws exceptions on error
    $this->otp->send($identifier);
}
```

### Custom Identifier Types

Create custom identifier types for phones, usernames, or any identifier format you need.

**Step 1: Create Type Class**

```php
// app/Otp/BangladeshSmsType.php
namespace App\Otp;

use Biponix\SecureOtp\Contracts\OtpIdentifierType;

class BangladeshSmsType extends OtpIdentifierType
{
    /**
     * Normalize Bangladesh phone numbers to E.164 format
     */
    public function normalize(string $value): string
    {
        // Remove spaces, dashes, parentheses
        $value = preg_replace('/[\s\-\(\)]/', '', $value);

        // Convert local format (01700000000) to E.164 (+8801700000000)
        if (preg_match('/^0\d{10}$/', $value)) {
            return '+880' . substr($value, 1);
        }

        return $value;
    }

    /**
     * Validate E.164 Bangladesh phone numbers
     */
    public function validate(string $value): bool
    {
        // Must be +880 followed by 10 digits
        return preg_match('/^\+880\d{10}$/', $value) === 1;
    }
}
```

**Step 2: Register Type in AppServiceProvider**

```php
// app/Providers/AppServiceProvider.php
use App\Otp\BangladeshSmsType;
use Biponix\SecureOtp\Services\SecureOtpService;

public function boot(): void
{
    // Register custom identifier types
    SecureOtpService::addType('sms', new BangladeshSmsType());
}
```

**Step 3: Use With Type Parameter**

```php
// Send OTP with validation
$otp->send('01700000000', 'sms');      // ✅ Normalized to +8801700000000
$otp->send('0170-000-0000', 'sms');    // ✅ Normalized to +8801700000000

// Verify with same type
$verified = $otp->verify('01700000000', '123456', 'sms');  // ✅ Works!
```

**More Examples:**

```php
// Username type
class UsernameType extends OtpIdentifierType
{
    public function normalize(string $value): string
    {
        return strtolower(trim($value));
    }

    public function validate(string $value): bool
    {
        return preg_match('/^[a-z0-9_]{3,20}$/', $value) === 1;
    }
}

// User ID type
class UserIdType extends OtpIdentifierType
{
    public function normalize(string $value): string
    {
        return trim($value);
    }

    public function validate(string $value): bool
    {
        return ctype_digit($value) && (int)$value > 0;
    }
}

// Register in AppServiceProvider
SecureOtpService::addType('username', new UsernameType());
SecureOtpService::addType('user_id', new UserIdType());

// Usage
$otp->send('john_doe', 'username');
$otp->send('12345', 'user_id');
```

### Generate Without Sending (Custom Delivery)

```php
use Biponix\SecureOtp\Services\SecureOtpService;
use Biponix\SecureOtp\Exceptions\RateLimitExceededException;

public function customDelivery(SecureOtpService $otp)
{
    try {
        // Generate OTP without sending (returns string)
        $code = $otp->generate('user@example.com', 'email');

        // Deliver via your custom method
        $this->sendViaSms($code);

    } catch (RateLimitExceededException $e) {
        // Handle rate limiting
        return response()->json([
            'error' => 'Too many requests',
            'retry_after' => $e->getRetryAfter(),
        ], 429);
    }
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

// Send OTP (throws exceptions on error)
SecureOtp::send('user@example.com');

// Verify OTP (returns bool)
$verified = SecureOtp::verify('user@example.com', '123456');

// Generate without sending (returns string, throws on rate limit)
$code = SecureOtp::generate('user@example.com');

// Send synchronously (throws exceptions on error)
SecureOtp::sendNow('user@example.com');
```

### Custom Notification Channels

Create your own notification class to route OTPs via SMS, WhatsApp, or other channels based on identifier type.

**Type-Based Channel Routing:**

```php
// app/Notifications/MultiChannelOtpNotification.php
namespace App\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Messages\VonageSmsMessage;
use Illuminate\Notifications\Notification;

class MultiChannelOtpNotification extends Notification
{
    public function __construct(public string $code) {}

    /**
     * Route notification channels based on identifier type
     */
    public function via(object $notifiable): array
    {
        // $notifiable->type comes from SecureOtpService::send($identifier, $type)
        return match ($notifiable->type) {
            'sms' => ['vonage'],           // Phone via SMS
            'email' => ['mail'],           // Email
            'whatsapp' => ['whatsapp'],    // WhatsApp (if configured)
            default => ['mail'],           // Fallback to email
        };
    }

    /**
     * SMS notification
     */
    public function toVonage(object $notifiable): VonageSmsMessage
    {
        return (new VonageSmsMessage)
            ->content("Your verification code is: {$this->code}");
    }

    /**
     * Email notification
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Your Verification Code')
            ->line("Your verification code is: {$this->code}")
            ->line('This code will expire in ' . config('secure-otp.expiry_minutes', 5) . ' minutes.');
    }
}
```

**Register Your Notification:**

Update your `.env`:

```env
OTP_NOTIFICATION_CLASS="App\Notifications\MultiChannelOtpNotification"
```

**Usage:**

```php
// Sends via Vonage SMS
$otp->send('01700000000', 'sms');

// Sends via Email
$otp->send('user@example.com', 'email');

// Sends via WhatsApp (if configured)
$otp->send('+8801700000000', 'whatsapp');
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

### `generate(string $identifier, ?string $type = null): string`

Generates an OTP code without sending it (for custom delivery methods).

**Parameters:**
- `$identifier` (string): Email, phone, username, or any identifier
- `$type` (string|null): Optional. Identifier type for validation/normalization (e.g., 'email', 'sms', 'username')

**Returns:**
- `string`: The generated OTP code

**Throws:**
- `RateLimitExceededException`: If rate limit is exceeded
- `InvalidIdentifierException`: If security check fails or type validation fails
- `OtpGenerationException`: If OTP generation fails

**Examples:**
```php
try {
    $code = $otp->generate('user@example.com', 'email');  // With validation
    $code = $otp->generate('01700000000');                // Without validation
} catch (RateLimitExceededException $e) {
    // Handle rate limiting: $e->getRetryAfter() gives seconds until retry
}
```

---

### `send(string $identifier, ?string $type = null): void`

Generates and queues an OTP notification to the given identifier (non-blocking).

**Parameters:**
- `$identifier` (string): Email, phone, username, or any identifier
- `$type` (string|null): Optional. Identifier type for validation/normalization

**Returns:**
- `void`

**Throws:**
- `RateLimitExceededException`: If rate limit is exceeded
- `InvalidIdentifierException`: If security check fails or type validation fails
- `OtpGenerationException`: If OTP generation/sending fails

**Examples:**
```php
try {
    $otp->send('user@example.com', 'email');    // Email with validation
    $otp->send('01700000000', 'sms');           // Phone with SMS type
    $otp->send('username123');                  // No validation
} catch (RateLimitExceededException $e) {
    // Return HTTP 429 with retry_after header
}
```

---

### `sendNow(string $identifier, ?string $type = null): void`

Generates and sends an OTP synchronously to the given identifier (blocks until sent).

**Parameters:**
- `$identifier` (string): Email, phone, username, or any identifier
- `$type` (string|null): Optional. Identifier type for validation/normalization

**Returns:**
- `void`

**Throws:**
- `RateLimitExceededException`: If rate limit is exceeded
- `InvalidIdentifierException`: If security check fails or type validation fails
- `OtpGenerationException`: If OTP generation/sending fails

---

### `verify(string $identifier, string $code, ?string $type = null): bool`

Verifies an OTP code for the given identifier.

**Parameters:**
- `$identifier` (string): Email, phone, username, or any identifier
- `$code` (string): The OTP code to verify (default 6 digits)
- `$type` (string|null): Optional. Must match the type used in `send()` for normalization consistency

**Returns:**
- `true`: OTP verified successfully
- `false`: Verification failed (invalid, expired, max attempts exceeded, etc.)

**Important:** The `$type` parameter must match what was used when sending the OTP to ensure proper normalization.

**Examples:**
```php
$verified = $otp->verify('user@example.com', '123456', 'email');
$verified = $otp->verify('01700000000', '123456', 'sms');  // Same type as send()
```

---

### `addType(string $name, OtpIdentifierType $type): void`

Register a custom identifier type for validation and normalization.

**Parameters:**
- `$name` (string): Type name (e.g., 'sms', 'email', 'username')
- `$type` (OtpIdentifierType): Type implementation

**Example:**
```php
SecureOtpService::addType('sms', new BangladeshSmsType());
```

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

The package maintains **100% code coverage** with 103 comprehensive tests covering all security features, edge cases, and error scenarios.

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
