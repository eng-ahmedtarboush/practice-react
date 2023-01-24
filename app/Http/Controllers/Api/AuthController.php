<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    function __construct()
    {
        $this->middleware('auth.sanctum', ['except' => ['login', 'register']]);
        $this->middleware('guest', ['only' => ['login', 'register']]);
    }

    public function register(RegisterRequest $request)
    {
        $data = $request->validated();
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'phone_number' => $data['phone_number'],
            'password' => bcrypt($data['password'])
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'success' => true,
            'message' => 'Successfully created user!',
            'data' => [
                'user' => $user->only('name', 'email', 'phone_number'),
                'token' => $token
            ]
        ], 201);
    }

    public function login(Request $request)
    {
        if (auth()->check()):
            return response()->json(['success'=>false, 'message' => 'Already logged in','data'=>[]], 400);
        endif;

        $credentials = $request->validate([
            'email' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:8'],
        ], [
            "email.required" => "البريد الالكتروني مطلوب",
            "email.string" => "البريد الالكتروني يجب ان يكون حروف",
            "email.email" => "الرجاء ادخال البريد الالكتروني بشكل صحيح",
            "email.max" => "أكبر عدد ممكن من الحروف هو 255 حرف",
            "email.exists" => "هناك خطأ في البريد الالكتروني أو كلمة المرور",

            'password.required' => "كلمة المرور مطلوبة",
            'password.string' => "يجب أن تكون كلمة المرور عبارة عن نص",
            'password.min' => "أقل عدد ممكن من الحروف هو 8 حروف",
        ]);

        if (is_numeric(request()->get('email'))) {
            $credentials = ['phone_number' => $credentials['email'], 'password' => $credentials['password']];
        }

        if (auth()->attempt($credentials)) {
            if (auth()->user()->tokens()->count() >= config('zircon.max_login_attempts')) {
                auth()->user()->currentAccessToken()->delete();
                return response()->json(['success' => false, 'message' => 'لقد تجاوزت الحد الاقصى من محاولات الدخول', 'data' => []], 403);
            }else{
                return response()->json([
                    'success' => true,
                    'message' => 'تم تسجيل الدخول بنجاح',
                    'data' => [
                        'token' => auth()->user()->createToken('auth_token')->plainTextToken,
                        'user' => auth()->user()->only(['name', 'email', 'phone_number'])
                    ]
                ], 200);
            }
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }

    public function logout()
    {
        if (auth()->check()):
            auth()->user()->currentAccessToken()->delete();
            return response()->json(['success'=>true, 'message' => 'Successfully logged out','data'=>[]], 200);
        else:
            return response()->json(['success'=>false, 'message' => 'Not logged in','data'=>[]], 400);
        endif;
    }
}
