<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Support;

use Illuminate\Notifications\Notifiable;

/**
 * On-Demand Notifiable
 *
 * Used for sending notifications to identifiers (email/phone) without a model.
 * This class allows the notification's via() method to control all channels.
 */
class OnDemandNotifiable
{
    use Notifiable;

    /**
     * Create a new on-demand notifiable instance.
     */
    public function __construct(public string $identifier) {}

    /**
     * Get the notification routing key.
     */
    public function getKey(): string
    {
        return $this->identifier;
    }

    /**
     * Route notifications for the given channel.
     */
    public function routeNotificationFor(string $driver): string
    {
        return $this->identifier;
    }
}
