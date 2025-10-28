<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Exceptions;

use Exception;

class InvalidIdentifierException extends Exception
{
    public function __construct()
    {
        parent::__construct('Invalid identifier format provided');
    }
}
