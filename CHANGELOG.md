# Changelog

All notable changes to `laravel-simple-otp` will be documented in this file.

## 1.0.0 - 2025-10-28

### Added
- Initial release
- Production-grade OTP generation and verification service
- Multi-channel notification support (Email, SMS, WhatsApp, Telegram)
- Secure hash-based storage (SHA-256)
- Timing-attack resistant verification
- Multi-layer rate limiting (per identifier + per IP)
- Replay attack prevention
- Race condition protection with database transactions
- Generic responses to prevent enumeration attacks
- Comprehensive security logging
- Configurable OTP length, expiry, and attempts
- Custom notification class support
- Automated OTP cleanup with `simple-otp:clean` artisan command
- Email and phone identifier support (E.164 format)
- Full Laravel 11 & 12 support
- Multi-tenancy support
- 53 comprehensive tests with 100% code coverage
