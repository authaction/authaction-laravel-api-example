<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use UnexpectedValueException;

class AuthActionJWT
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Unauthorized: missing token'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $payload = $this->verifyToken($token);
            $request->attributes->set('jwt_payload', $payload);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }

        return $next($request);
    }

    private function verifyToken(string $token): object
    {
        $domain   = config('authaction.domain');
        $audience = config('authaction.audience');
        $issuer   = "https://{$domain}";

        try {
            $keys    = JWK::parseKeySet($this->getJwks($domain));
            $payload = JWT::decode($token, $keys);
        } catch (ExpiredException) {
            throw new \Exception('Token has expired');
        } catch (UnexpectedValueException $e) {
            // kid not found — possible key rotation; bust cache and retry once
            if (str_contains($e->getMessage(), 'kid')) {
                Cache::forget("authaction_jwks_{$domain}");
                $keys    = JWK::parseKeySet($this->getJwks($domain));
                $payload = JWT::decode($token, $keys);
            } else {
                throw new \Exception($e->getMessage());
            }
        }

        if (($payload->iss ?? '') !== $issuer) {
            throw new \Exception('Invalid issuer');
        }

        $aud = isset($payload->aud)
            ? (array) $payload->aud
            : [];

        if (!in_array($audience, $aud, strict: true)) {
            throw new \Exception('Invalid audience');
        }

        Log::debug('JWT validated', ['sub' => $payload->sub ?? null]);

        return $payload;
    }

    private function getJwks(string $domain): array
    {
        return Cache::remember("authaction_jwks_{$domain}", ttl: 3600, callback: function () use ($domain) {
            $response = Http::get("https://{$domain}/.well-known/jwks.json");
            $response->throw();
            return $response->json();
        });
    }
}
