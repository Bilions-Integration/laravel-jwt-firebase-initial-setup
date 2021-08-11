<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Kreait\Firebase\Factory;

class AuthController extends Controller {
  /**
   * Logout User
   */
  public function logout() {
    try {
      $this->guard()->logout();
      return response()->json([
        'status' => 'success',
        'msg'    => 'Logged out Successfully.',
      ], 200);
    } catch (Exception $e) {
      return response($e->getMessage(), 500);
    }
  }

  /**
   * Get authenticated user
   */
  public function user() {
    $user = User::find(Auth::user()->id);
    return response()->json([
      'status' => 'success',
      'data'   => $user,
    ]);
  }

  /**
   * Refresh JWT token
   */
  public function refresh() {
    try {
      if ($token = $this->guard()->refresh()) {
        return response()
          ->json(['status' => 'successs', 'token' => $token], 200)
          ->header('Authorization', $token);
      }
      return response()->json(['error' => 'refresh_token_error'], 401);
    } catch (\Exception $exception) {
      return response()->json(['error' => $exception->getMessage()], 401);
    }
  }

  /**
   * @param Request $request
   * verify token
   */
  public function verifyToken(Request $request) {
    request()->validate([
      'token' => 'required',
      'type'  => 'required',
    ]);
    $factory = (new Factory)->withServiceAccount(__DIR__ . '/firebase.json');
    $auth    = $factory->createAuth();
    try {
      if (env('APP_ENV') === 'production') {
        $verifiedIdToken = $auth->verifyIdToken($request->token);
        $uid             = $verifiedIdToken->getClaim('sub');
        $firebaseUser    = $auth->getUser($uid);
        $user            = User::where('firebase_uid', $uid)->first();
        if (!$user) {
          $user = User::create([
            'email'        => $firebaseUser->email,
            'firebase_uid' => $uid,
            'login_type'   => $request->type,
          ]);
        }
      } else {
        $user = User::find(1);
      }
      if ($token = $this->guard()->login($user)) {
        return response()
          ->json(['status' => 'success', 'token' => $token], 200)
          ->header('Authorization', $token);
      }
    } catch (Exception $e) {
      return response()->json(['error' => $e->getMessage()], 401);
    }
  }

  /**
   * fcm token update
   */
  public function fcm_token(Request $request) {
    try {
      request()->validate([
        'fcm_token' => 'required',
      ]);
      $user            = User::find(Auth::user()->id);
      $user->fcm_token = $request->fcm_token;
      $user->save();
      return response()
        ->json(['success' => true, 'message' => 'fcm_token updated'], 200);
    } catch (Exception $e) {
      return response()->json(['error' => $e->getMessage()], 500);
    }
  }

  /**
   * Return auth guard
   */
  private function guard() {
    return Auth::guard();
  }
}