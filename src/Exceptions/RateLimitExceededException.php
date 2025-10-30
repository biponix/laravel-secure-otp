<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Exceptions;

use Exception;

class RateLimitExceededException extends Exception
{
    public function __construct(
        string $message = 'Rate limit exceeded',
        public readonly ?int $availableIn = null,
        public readonly ?string $key = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Get seconds until rate limit resets
     */
    public function getRetryAfter(): ?int
    {
        return $this->availableIn;
    }

    /**
     * Get the rate limit key that was exceeded
     */
    public function getRateLimitKey(): ?string
    {
        return $this->key;
    }
}
