<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
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

    public function register(Request $request)
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token');
//        $validator = Validator::make($request->all(), [
//            'name' => ['required', 'string', 'max:255'],
//            'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
//            'password' => ['required', 'string', 'min:8', 'confirmed'],
//            'phone_number' => ['required', 'string', 'unique:users,phone_number', 'size:11']
//        ], [
//            'name.required' => "الاسم مطلوب",
//            'name.string' => "الاسم يجب ان يكون حروف",
//            'name.max' => "أكبر عدد ممكن من الحروف هو 255 حرف",
//
//            'email.required' => "البريد الالكتروني مطلوب",
//            'email.string' => "البريد الالكتروني يجب ان يكون حروف",
//            'email.email' => "البرجاء ادخال البريد الالكتروني بشكل صحيح",
//            'email.max' => "أكبر عدد ممكن من الحروف هو 255 حرف",
//            'email.unique' => "البريد الالكتروني موجود مسبقا",
//
//            'password.required' => "كلمة المرور مطلوبة",
//            'password.string' => "يجب أن تكون كلمة المرور عبارة عن نص",
//            'password.min' => "أقل عدد ممكن من الحروف هو 8 حروف",
//            'password.confirmed' => "كلمة السر غير متطابقة",
//
//            'phone_number.required' => "رقم الهاتف مطلوب",
//            'phone_number.unique' => "رقم الهاتف موجود بالفعل",
//            'phone_number.size' => "يجب أن يكون عدد الأرقام عن 11 رقم",
//            'phone_number.min' => "يجب أن لا يقل عدد الأرقام عن 11 رقم",
//            'phone_number.starts_with' => "يجب أن يبدأ رقم الهاتف بـ0",
//        ]);
//        if ($validator->fails()) {
//            dd($validator->errors());
//            return response()->json(['success'=>false, 'message'=>_('هناك خطأ في صحة البيانات'), 'data'=>$validator->errors()], 400);
//        }
//        $data = $validator->validated();

        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'phone_number' => 'required|string|unique:users',
            'password' => 'required|string|confirmed',
        ],[
            'name.required' => 'الاسم مطلوب',

            'email.required' => 'البريد الالكتروني مطلوب',
            'email.email' => 'البريد الالكتروني غير صحيح',
            'email.unique' => 'البريد الالكتروني مستخدم من قبل',

            'phone_number.required' => 'رقم الهاتف مطلوب',
            'phone_number.unique' => 'رقم الهاتف مستخدم من قبل',

            'password.required' => 'كلمة المرور مطلوبة',
            'password.confirmed' => 'كلمة المرور غير متطابقة',
        ]);
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone_number' => $request->phone_number,
            'password' => bcrypt($request->password)
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
