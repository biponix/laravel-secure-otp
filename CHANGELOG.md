# Changelog

All notable changes to `laravel-simple-otp` will be documented in this file.

## 1.0.0 - 2025-01-30

### Initial Release

A production-ready, secure OTP (One-Time Password) package for Laravel applications with multi-channel support and comprehensive security features.

#### Core Features

- **Production-Grade Security**
  - HMAC-based OTP storage with SHA-256 hashing
  - Timing-attack resistant verification with `hash_equals()`
  - Replay attack prevention (previous OTPs auto-invalidated)
  - Race condition protection using distributed cache locks
  - Generic boolean responses to prevent enumeration attacks

- **Multi-Channel Notification Support**
  - Email, SMS, WhatsApp, Telegram (via Laravel Notifications)
  - Custom notification class support via config
  - Type-based channel routing capabilities

- **Pluggable Identifier Type System**
  - Accept any identifier format by default (emails, phones, usernames, user IDs, etc.)
  - Optional type registration for validation and normalization
  - Built-in `EmailType` with lowercase normalization
  - Create custom types with `OtpIdentifierType` abstract class
  - Example: Bangladesh phone normalization (01700000000 → +8801700000000)

- **Context-Aware Rate Limiting**
  - Separate limits for generation vs verification (brute force protection)
  - Per-identifier rate limiting (prevents spam to specific user)
  - Per-IP rate limiting in HTTP contexts (prevents mass abuse)
  - Configurable limits with independent enable/disable per axis
  - Smart detection: IP limiting automatically skipped in queue/console contexts

- **Developer Experience**
  - Simple, intuitive API: `send()`, `sendNow()`, `generate()`, `verify()`
  - Dependency injection support
  - Optional facade (`SecureOtp::send()`)
  - Queue-friendly (works in HTTP, queue workers, console)
  - Comprehensive error handling with custom exceptions

- **Security Logging**
  - Detailed audit logs for all security events
  - Privacy-preserving PII masking (emails: `te***@example.com`, phones: `***7890`)
  - Configurable logging via `OTP_ENABLE_LOGGING`
  - Logs: generation, verification attempts, rate limits, validation failures

- **Automated Cleanup**
  - `simple-otp:clean` artisan command for expired OTP removal
  - Configurable retention period (`OTP_CLEANUP_AFTER_HOURS`)
  - Designed for Laravel scheduler integration
  - Supports `--force` flag for production use

- **Testing & Quality**
  - 104 comprehensive tests with 100% code coverage
  - Parameterized tests using Pest datasets
  - Tests cover all security features, edge cases, and error scenarios
  - Full Laravel 11 & 12 compatibility
  - PHP 8.1-8.4 support

#### Configuration Options

- OTP length (default: 6 digits)
- Expiry time (default: 5 minutes)
- Max verification attempts (default: 3)
- Custom hash algorithm and secret
- Rate limiting configuration (per-identifier, per-IP, separate for verify)
- Custom notification class
- Cleanup retention period
- Security logging toggle

#### Security Highlights

1. **No Plain Text Storage**: OTPs are hashed with HMAC before storage
2. **Timing-Safe Comparison**: Prevents timing attacks during verification
3. **Rate Limiting**: Multi-layer protection against brute force
4. **Replay Prevention**: Old OTPs automatically invalidated
5. **Race Condition Safe**: Distributed locks + database transactions
6. **Enumeration Protection**: Generic error responses
7. **Audit Trail**: Comprehensive security logging with PII masking

#### Example Usage

```php
use Biponix\SecureOtp\Services\SecureOtpService;
use Biponix\SecureOtp\Types\EmailType;

// Basic usage (no validation)
$otp = app(SecureOtpService::class);
$otp->send('user@example.com');
$verified = $otp->verify('user@example.com', '123456');

// With type validation
SecureOtpService::addType('email', new EmailType());
$otp->send('user@example.com', 'email'); // Validated & normalized

// Custom type for Bangladesh phones
class BangladeshSmsType extends OtpIdentifierType {
    public function normalize(string $value): string {
        $clean = preg_replace('/[\s\-\(\)]/', '', $value);
        if (preg_match('/^0\d{10}$/', $clean)) {
            return '+880' . substr($clean, 1);
        }
        return $clean;
    }

    public function validate(string $value): bool {
        return preg_match('/^\+880\d{10}$/', $value) === 1;
    }
}

SecureOtpService::addType('sms', new BangladeshSmsType());
$otp->send('01700000000', 'sms'); // Normalized to +8801700000000
```

#### Migration & Installation

```bash
composer require biponix/laravel-secure-otp
php artisan migrate
php artisan vendor:publish --tag="secure-otp-config"
```

See [README.md](README.md) for complete documentation.
