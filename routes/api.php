<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/public', function () {
    return response()->json(['message' => 'This is a public message!']);
});

Route::middleware('auth.jwt')->get('/protected', function (Request $request) {
    $payload = $request->attributes->get('jwt_payload');

    return response()->json([
        'message' => 'This is a protected message!',
        'sub' => $payload->sub,
    ]);
});
