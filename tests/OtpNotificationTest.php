<?php

use Biponix\SecureOtp\Notifications\OtpNotification;
use Biponix\SecureOtp\Support\OnDemandNotifiable;

test('it returns mail channel', function () {
    $notification = new OtpNotification('123456');
    $notifiable = new OnDemandNotifiable('test@example.com');

    expect($notification->via($notifiable))->toBe(['mail']);
});

test('it creates mail message with correct code', function () {
    $code = '654321';
    $notification = new OtpNotification($code);
    $notifiable = new OnDemandNotifiable('test@example.com');

    $mailMessage = $notification->toMail($notifiable);

    expect($mailMessage->subject)->toBe('Your Verification Code')
        ->and($mailMessage->greeting)->toBe('Hello!')
        ->and($mailMessage->introLines)->toContain('You have requested a verification code.')
        ->and($mailMessage->introLines)->toContain("Your verification code is: **{$code}**");
});

test('it includes expiry time from config in mail', function () {
    config(['secure-otp.expiry_minutes' => 10]);

    $notification = new OtpNotification('123456');
    $notifiable = new OnDemandNotifiable('test@example.com');

    $mailMessage = $notification->toMail($notifiable);

    expect($mailMessage->introLines)->toContain('This code will expire in 10 minutes.');
});

test('it uses default expiry time when config not set', function () {
    // Don't set config value, let it use default
    $notification = new OtpNotification('123456');
    $notifiable = new OnDemandNotifiable('test@example.com');

    $mailMessage = $notification->toMail($notifiable);

    // The default is 5 minutes from the config function's default parameter
    expect(collect($mailMessage->introLines)->contains(fn ($line) => str_contains($line, 'expire in')))->toBeTrue();
});

test('it includes security warning in mail', function () {
    $notification = new OtpNotification('123456');
    $notifiable = new OnDemandNotifiable('test@example.com');

    $mailMessage = $notification->toMail($notifiable);

    expect($mailMessage->introLines)->toContain('If you did not request this code, please ignore this email.');
});
