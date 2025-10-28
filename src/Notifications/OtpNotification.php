<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Default OTP Notification
 *
 * This is the default notification provided by the package.
 * You can replace it by setting OTP_NOTIFICATION_CLASS in your .env file.
 *
 * Currently supports: Email
 * Coming soon: SMS, WhatsApp, Telegram
 */
class OtpNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     *
     * @param  string  $code  The OTP code to send
     */
    public function __construct(
        public string $code
    ) {}

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $expiryMinutes = config('secure-otp.expiry_minutes', 5);

        return (new MailMessage)
            ->subject('Your Verification Code')
            ->greeting('Hello!')
            ->line('You have requested a verification code.')
            ->line("Your verification code is: **{$this->code}**")
            ->line("This code will expire in {$expiryMinutes} minutes.")
            ->line('If you did not request this code, please ignore this email.');
    }
}
