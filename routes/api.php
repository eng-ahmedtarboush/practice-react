<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::get('/user', function (Request $request) {
    return ['انا تماااام'];
//    return $request->user()->only(['name', 'email', 'phone_number']);
});
Route::get('/', function () {
    return '';
});
Route::post('/register', [AuthController::class , 'register'])->name('register');
Route::post('/login', [AuthController::class , 'login'])->name('login');
Route::post('/logout', [AuthController::class , 'logout'])->name('logout');
