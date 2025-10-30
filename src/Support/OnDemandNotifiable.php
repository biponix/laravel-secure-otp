<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Support;

use Illuminate\Notifications\Notifiable;

/**
 * On-Demand Notifiable
 *
 * Used for sending notifications to identifiers (email/phone/username/etc) without a model.
 * This class allows the notification's via() method to control all channels.
 *
 * The $type property is passed to the notification's via() method, allowing it to
 * make channel routing decisions based on the identifier type.
 */
class OnDemandNotifiable
{
    use Notifiable;

    /**
     * Create a new on-demand notifiable instance.
     *
     * @param  string  $identifier  The identifier value (email, phone, username, etc.)
     * @param  string|null  $type  The identifier type (e.g., 'email', 'sms', 'username')
     */
    public function __construct(
        public string $identifier,
        public ?string $type = null
    ) {}

    /**
     * Get the notification routing key.
     */
    public function getKey(): string
    {
        return $this->identifier;
    }

    /**
     * Route notifications for the given channel.
     *
     * Returns the identifier for all channels. The notification's via() method
     * decides which channels to use based on the type property.
     */
    public function routeNotificationFor(string $driver): string
    {
        return $this->identifier;
    }
}
