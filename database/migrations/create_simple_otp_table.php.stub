<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('secure_otps', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('identifier')->index(); // phone or email
            $table->string('code_hash'); // hashed code (SHA-256)
            $table->integer('attempts')->default(0); // verification attempts
            $table->timestamp('expires_at')->index();
            $table->timestamp('verified_at')->nullable()->index();
            $table->timestamp('created_at');

            // Composite index for fast lookups
            $table->index(['identifier', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('secure_otps');
    }
};
