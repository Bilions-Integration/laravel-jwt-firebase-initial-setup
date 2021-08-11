<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateUsersTable extends Migration {
  /**
   * Run the migrations.
   *
   * @return void
   */
  public function up() {
    Schema::create('users', function (Blueprint $table) {
      $table->id();
      $table->string('name');
      $table->string('email');
      $table->string('firebase_uid')->unique();
      $table->enum('login_type', ['google', 'facebook', 'email', 'apple', 'phone'])->default('email');
      $table->timestamp('email_verified_at')->nullable();
      $table->string('password')->nullable();
      $table->string('fcm_token')->nullable();
      $table->rememberToken();
      $table->timestamps();
    });
  }

  /**
   * Reverse the migrations.
   *
   * @return void
   */
  public function down() {
    Schema::dropIfExists('users');
  }
}
