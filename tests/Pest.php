<?php

use Biponix\SecureOtp\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);

// Ensure proper teardown to avoid error handler conflicts
uses()->afterEach(function () {
    // Clean up any lingering state that might affect error handlers
    Mockery::close();
})->in(__DIR__);
