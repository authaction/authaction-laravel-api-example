<?php

namespace App\Http\Middleware;

use AuthAction\AuthAction;
use AuthAction\Middleware\LaravelMiddleware;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthActionJWT
{
    private readonly LaravelMiddleware $inner;

    public function __construct()
    {
        $aa = new AuthAction(
            config('authaction.domain'),
            config('authaction.audience')
        );
        $this->inner = new LaravelMiddleware($aa);
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $this->inner->handle($request, $next);
    }
}
