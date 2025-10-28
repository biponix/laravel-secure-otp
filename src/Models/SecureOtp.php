<?php

declare(strict_types=1);

namespace Biponix\SecureOtp\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * SecureOtp Model
 *
 * @property string $id UUID primary key
 * @property string $identifier Phone number or email address
 * @property string $code_hash Hashed OTP code (SHA-256)
 * @property int $attempts Number of verification attempts
 * @property Carbon $expires_at Expiration timestamp
 * @property Carbon|null $verified_at Verification timestamp
 * @property Carbon $created_at Creation timestamp
 */
class SecureOtp extends Model
{
    use HasUuids;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'secure_otps';

    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'id';

    /**
     * Indicates if the IDs are auto-incrementing.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * The data type of the auto-incrementing ID.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'identifier',
        'code_hash',
        'attempts',
        'expires_at',
        'verified_at',
        'created_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'attempts' => 'integer',
        'expires_at' => 'datetime',
        'verified_at' => 'datetime',
        'created_at' => 'datetime',
    ];

    /**
     * Scope to get only valid (unverified and not expired) OTPs
     */
    public function scopeValid(Builder $query): Builder
    {
        return $query->whereNull('verified_at')
            ->where('expires_at', '>', now());
    }

    /**
     * Scope to get OTPs for a specific identifier
     */
    public function scopeForIdentifier(Builder $query, string $identifier): Builder
    {
        return $query->where('identifier', $identifier);
    }

    /**
     * Scope to get expired OTPs
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('expires_at', '<', now());
    }

    /**
     * Check if OTP is verified
     */
    public function isVerified(): bool
    {
        return $this->verified_at !== null;
    }

    /**
     * Check if OTP is expired
     */
    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    /**
     * Check if max attempts reached
     */
    public function hasMaxAttemptsReached(): bool
    {
        $maxAttempts = config('secure-otp.max_attempts', 3);

        return $this->attempts >= $maxAttempts;
    }

    /**
     * Mark OTP as verified
     */
    public function markAsVerified(): bool
    {
        $this->verified_at = now();

        return $this->save();
    }

    /**
     * Increment verification attempts
     */
    public function incrementAttempts(): bool
    {
        $this->attempts++;

        return $this->save();
    }
}
