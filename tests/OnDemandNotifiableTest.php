<?php

use Biponix\SecureOtp\Support\OnDemandNotifiable;

test('it stores identifier correctly', function () {
    $identifier = 'test@example.com';
    $notifiable = new OnDemandNotifiable($identifier);

    expect($notifiable->identifier)->toBe($identifier);
});

test('it returns identifier as key', function () {
    $identifier = '+1234567890';
    $notifiable = new OnDemandNotifiable($identifier);

    expect($notifiable->getKey())->toBe($identifier);
});

test('it routes notifications to identifier', function () {
    $identifier = 'test@example.com';
    $notifiable = new OnDemandNotifiable($identifier);

    expect($notifiable->routeNotificationFor('mail'))->toBe($identifier)
        ->and($notifiable->routeNotificationFor('sms'))->toBe($identifier)
        ->and($notifiable->routeNotificationFor('any-channel'))->toBe($identifier);
});
