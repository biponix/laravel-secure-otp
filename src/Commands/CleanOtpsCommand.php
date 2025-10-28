<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Commands;

use Biponix\SecureOtp\Services\SecureOtpService;
use Illuminate\Console\Command;

class CleanOtpsCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'secure-otp:clean
                            {--force : Force the operation to run in production}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clean up expired OTP records from the database';

    /**
     * Execute the console command.
     */
    public function handle(SecureOtpService $otpService): int
    {
        if ($this->getLaravel()->environment('production') && ! $this->option('force')) {
            $this->error('Use --force to run in production environment');

            return self::FAILURE;
        }

        $this->info('Cleaning up expired OTPs...');

        $deleted = $otpService->cleanupExpired();

        if ($deleted > 0) {
            $this->info("Successfully deleted {$deleted} expired OTP record(s).");
        } else {
            $this->info('No expired OTPs found.');
        }

        return self::SUCCESS;
    }
}
