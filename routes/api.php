<?php

use Illuminate\Support\Facades\Route;

Route::prefix('auth')->group(function () {
  Route::get('refresh', 'AuthController@refresh');
  Route::post('login', 'AuthController@verifyToken');
  Route::middleware('auth:api')->group(function () {
    Route::get('user', 'AuthController@user');
    Route::put('fcm', 'AuthController@fcm_token');
  });
});