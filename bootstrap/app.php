<?php

use App\Http\Middleware\AuthActionJWT;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        apiPrefix: '',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'auth.jwt' => AuthActionJWT::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })
    ->create();
