<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthenticateSanctum
{
    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
//    protected function redirectTo($request)
//    {
//        if (!$request->expectsJson()) {
//            return response()->json([
//                'success' => false,
//                'message' => 'Unauthenticated.',
//                'data'=>[]
//            ], 401);
//        }
//    }

    public function handle(Request $request, Closure $next)
    {
        if (auth()->guest()):
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated.',
                'data'=>[]
            ], 401);
        endif;
        return $next($request);
    }

}
