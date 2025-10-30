<?php

use Biponix\SecureOtp\Notifications\OtpNotification;
use Biponix\SecureOtp\Support\OnDemandNotifiable;

describe('OtpNotification', function () {
    it('returns mail channel by default', function () {
        $notification = new OtpNotification('123456');
        $notifiable = new OnDemandNotifiable('test@example.com');

        expect($notification->via($notifiable))->toBe(['mail']);
    });

    it('creates mail message with correct code', function () {
        $code = '654321';
        $notification = new OtpNotification($code);
        $notifiable = new OnDemandNotifiable('test@example.com');

        $mailMessage = $notification->toMail($notifiable);

        expect($mailMessage->subject)->toBe('Your Verification Code')
            ->and($mailMessage->greeting)->toBe('Hello!')
            ->and($mailMessage->introLines)->toContain('You have requested a verification code.')
            ->and($mailMessage->introLines)->toContain("Your verification code is: **{$code}**");
    });

    it('includes expiry time from config in mail', function () {
        config(['secure-otp.expiry_minutes' => 10]);

        $notification = new OtpNotification('123456');
        $notifiable = new OnDemandNotifiable('test@example.com');

        $mailMessage = $notification->toMail($notifiable);

        expect($mailMessage->introLines)->toContain('This code will expire in 10 minutes.');
    });

    it('includes security warning in mail', function () {
        $notification = new OtpNotification('123456');
        $notifiable = new OnDemandNotifiable('test@example.com');

        $mailMessage = $notification->toMail($notifiable);

        expect($mailMessage->introLines)->toContain('If you did not request this code, please ignore this email.');
    });
});
