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
 * Channel Routing:
 * - By default, sends via 'mail' channel only
 * - To customize channel routing based on identifier type, create your own notification:
 *
 * Example:
 * ```php
 * class MyOtpNotification extends Notification
 * {
 *     public function __construct(public string $code) {}
 *
 *     public function via(object $notifiable): array
 *     {
 *         // Route based on identifier type
 *         return match ($notifiable->type) {
 *             'sms' => ['vonage'],           // Phone via SMS
 *             'email' => ['mail'],           // Email
 *             'whatsapp' => ['whatsapp'],    // WhatsApp
 *             default => ['mail'],           // Fallback to email
 *         };
 *     }
 *
 *     public function toVonage($notifiable) { ... }
 *     public function toMail($notifiable) { ... }
 * }
 * ```
 *
 * Then set: OTP_NOTIFICATION_CLASS=App\Notifications\MyOtpNotification
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
     * Default implementation sends via 'mail' only.
     * Override this method in your custom notification to route based on $notifiable->type.
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
