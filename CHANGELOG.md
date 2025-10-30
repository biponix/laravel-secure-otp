# Changelog

All notable changes to `laravel-simple-otp` will be documented in this file.

## Title: v1.0.0 - Production-Ready OTP Package - 2025-10-30

### Laravel Secure OTP v1.0.0

Production-ready OTP package for Laravel with multi-channel support, pluggable identifier types, and comprehensive security features.

#### 🚀 Highlights

- **🔐 Production-Grade Security**: HMAC storage, timing-attack resistant, rate limiting, replay prevention
- **🔌 Pluggable Identifier Types**: Support emails, phones, usernames, user IDs - or create custom types
- **📧 Multi-Channel Support**: Email, SMS, WhatsApp, Telegram via Laravel Notifications
- **⚡ Exception-Based API**: Clear error handling with specific exception types
- **🛡️ Context-Aware Rate Limiting**: Separate limits for generation vs verification (brute force protection)
- **🧪 100% Test Coverage**: 103 comprehensive tests covering all security features
- **📱 Laravel 10, 11, 12**: PHP 8.1-8.4 support

#### 📦 Installation

  ```bash
  composer require biponix/laravel-secure-otp
php artisan migrate

⚡ Quick Start

Basic Usage:
$otp = app(SecureOtpService::class);
$otp->send('user@example.com');
$verified = $otp->verify('user@example.com', '123456');

With Type Validation:
SecureOtpService::addType('email', new EmailType());
$otp->send('user@example.com', 'email'); // Validated & normalized

Custom Type (Bangladesh Phones):
class BangladeshSmsType extends OtpIdentifierType {
    public function normalize(string $value): string {
        // Convert 01700000000 → +8801700000000
    }
}

SecureOtpService::addType('sms', new BangladeshSmsType());
$otp->send('01700000000', 'sms');

🔐 Security Features

- ✅ HMAC-based storage (SHA-256)
- ✅ Timing-attack resistant verification
- ✅ Race condition protection (distributed locks)
- ✅ Replay attack prevention
- ✅ Multi-layer rate limiting (per-identifier + per-IP)
- ✅ Enumeration protection (generic responses)
- ✅ Security logging with PII masking

📚 Documentation

Full documentation: https://github.com/biponix/laravel-secure-otp#readme

🧪 Quality

- 103 tests with 100% code coverage
- PHPStan level 9 compliant
- Laravel Pint code style
- Comprehensive edge case testing

💡 Use Cases

- Two-factor authentication (2FA)
- Email/phone verification
- Passwordless login
- Transaction confirmation
- Password reset flows

  ```
## v1.0.0 - Production-Ready OTP Package - 2025-01-30

### Initial Release

A production-ready, secure OTP (One-Time Password) package for Laravel applications with multi-channel support, pluggable identifier types, and comprehensive security features.

#### 🚀 Highlights

- **🔐 Production-Grade Security**: HMAC storage, timing-attack resistant, rate limiting, replay prevention
- **🔌 Pluggable Identifier Types**: Support emails, phones, usernames, user IDs - or create custom types
- **📧 Multi-Channel Support**: Email, SMS, WhatsApp, Telegram via Laravel Notifications
- **⚡ Exception-Based API**: Clear error handling with specific exception types
- **🛡️ Context-Aware Rate Limiting**: Separate limits for generation vs verification (brute force protection)
- **🧪 100% Test Coverage**: 103 comprehensive tests covering all security features
- **📱 Laravel 10, 11, 12**: PHP 8.1-8.4 support

#### 📦 Core Features

**Production-Grade Security**

- HMAC-based OTP storage with SHA-256 hashing
- Timing-attack resistant verification with `hash_equals()`
- Replay attack prevention (previous OTPs auto-invalidated)
- Race condition protection using distributed cache locks
- Generic boolean responses to prevent enumeration attacks

**Multi-Channel Notification Support**

- Email, SMS, WhatsApp, Telegram (via Laravel Notifications)
- Custom notification class support via config
- Type-based channel routing capabilities

**Pluggable Identifier Type System**

- Accept any identifier format by default (emails, phones, usernames, user IDs, etc.)
- Optional type registration for validation and normalization
- Built-in `EmailType` with lowercase normalization
- Create custom types with `OtpIdentifierType` abstract class
- Example: Bangladesh phone normalization (01700000000 → +8801700000000)

**Exception-Based API Design**

All generation and sending methods throw specific exceptions instead of returning booleans:

- `RateLimitExceededException` - Rate limit exceeded (includes retry information)
- `InvalidIdentifierException` - Invalid identifier format
- `OtpGenerationException` - Generation/sending failures

This provides:

- Clear, explicit error handling
- Type-safe method signatures (`void` returns)
- Easy HTTP status code mapping (429, 400, 500)
- Better developer experience

**Context-Aware Rate Limiting**

- Separate limits for generation vs verification (brute force protection)
- Per-identifier rate limiting (prevents spam to specific user)
- Per-IP rate limiting in HTTP contexts (prevents mass abuse)
- Configurable limits with independent enable/disable per axis
- Smart detection: IP limiting automatically skipped in queue/console contexts

**Developer Experience**

- Simple, intuitive API: `send()`, `sendNow()`, `generate()`, `verify()`
- Dependency injection support
- Optional facade (`SecureOtp::send()`)
- Queue-friendly (works in HTTP, queue workers, console)
- Comprehensive error handling with specific exception types

**Security Logging**

- Detailed audit logs for all security events
- Privacy-preserving PII masking (emails: `te***@example.com`, phones: `***7890`)
- Configurable logging via `OTP_ENABLE_LOGGING`
- Logs: generation, verification attempts, rate limits, validation failures

**Automated Cleanup**

- `secure-otp:clean` artisan command for expired OTP removal
- Configurable retention period (`OTP_CLEANUP_AFTER_HOURS`)
- Designed for Laravel scheduler integration
- Supports `--force` flag for production use

**Testing & Quality**

- 103 comprehensive tests with 100% code coverage
- Parameterized tests using Pest datasets
- Tests cover all security features, edge cases, and error scenarios
- Full Laravel 11 & 12 compatibility
- PHP 8.1-8.4 support

#### 📚 API Reference

**`generate(string $identifier, ?string $type = null): string`**

Generates an OTP code without sending it.

- **Returns**: `string` - The generated OTP code
- **Throws**:
  - `RateLimitExceededException` - If rate limit exceeded
  - `InvalidIdentifierException` - If identifier format invalid
  - `OtpGenerationException` - If generation fails
  

**`send(string $identifier, ?string $type = null): void`**

Generates and queues an OTP notification (non-blocking).

- **Returns**: `void`
- **Throws**:
  - `RateLimitExceededException` - If rate limit exceeded
  - `InvalidIdentifierException` - If identifier format invalid
  - `OtpGenerationException` - If sending fails
  

**`sendNow(string $identifier, ?string $type = null): void`**

Generates and sends an OTP synchronously (blocks until sent).

- **Returns**: `void`
- **Throws**: Same as `send()`

**`verify(string $identifier, string $code, ?string $type = null): bool`**

Verifies an OTP code.

- **Returns**: `bool` - True if verified, false otherwise (generic for security)

#### 💡 Usage Examples

**Basic Usage with Exception Handling**

```php
use Biponix\SecureOtp\Services\SecureOtpService;
use Biponix\SecureOtp\Exceptions\RateLimitExceededException;
use Biponix\SecureOtp\Exceptions\InvalidIdentifierException;
use Biponix\SecureOtp\Exceptions\OtpGenerationException;

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
            return response()->json([
                'error' => 'Too many requests',
                'retry_after' => $e->getRetryAfter(),
            ], 429);

        } catch (InvalidIdentifierException $e) {
            return response()->json([
                'error' => 'Invalid email address'
            ], 400);

        } catch (OtpGenerationException $e) {
            return response()->json([
                'error' => 'Failed to send OTP'
            ], 500);
        }
    }

    public function verifyOtp(Request $request, SecureOtpService $otp)
    {
        // verify() returns bool (doesn't expose why it failed)
        if ($otp->verify($request->email, $request->code, 'email')) {
            return response()->json(['message' => 'Verified successfully']);
        }

        return response()->json(['error' => 'Invalid or expired code'], 422);
    }
}

```
**Custom Identifier Types**

```php
// Bangladesh Phone Type
class BangladeshSmsType extends OtpIdentifierType
{
    public function normalize(string $value): string
    {
        $clean = preg_replace('/[\s\-\(\)]/', '', $value);
        if (preg_match('/^0\d{10}$/', $clean)) {
            return '+880' . substr($clean, 1);
        }
        return $clean;
    }

    public function validate(string $value): bool
    {
        return preg_match('/^\+880\d{10}$/', $value) === 1;
    }
}

// Register in AppServiceProvider
SecureOtpService::addType('sms', new BangladeshSmsType());

// Use with type
$otp->send('01700000000', 'sms'); // Normalized to +8801700000000

```
#### ⚙️ Configuration Options

- OTP length (default: 6 digits)
- Expiry time (default: 5 minutes)
- Max verification attempts (default: 3)
- Custom hash algorithm and secret
- Context-aware rate limiting (separate for generate/verify)
- Custom notification class
- Cleanup retention period
- Security logging toggle

#### 🔒 Security Highlights

1. **No Plain Text Storage**: OTPs are hashed with HMAC before storage
2. **Timing-Safe Comparison**: Prevents timing attacks during verification
3. **Multi-Layer Rate Limiting**: Per-identifier + per-IP protection
4. **Replay Prevention**: Old OTPs automatically invalidated
5. **Race Condition Safe**: Distributed locks + database transactions
6. **Enumeration Protection**: Generic error responses
7. **Audit Trail**: Comprehensive security logging with PII masking

#### 📦 Installation

```bash
composer require biponix/laravel-secure-otp
php artisan migrate
php artisan vendor:publish --tag="secure-otp-config"

```
See [README.md](README.md) for complete documentation.
