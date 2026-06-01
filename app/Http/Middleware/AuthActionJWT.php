<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Symfony\Component\HttpFoundation\Response;

class AuthActionJWT
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Unauthorized: missing token'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $parsed = $this->verifyToken($token);
            $request->attributes->set('jwt_payload', (object) $parsed->claims()->all());
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], Response::HTTP_UNAUTHORIZED);
        }

        return $next($request);
    }

    private function verifyToken(string $token): Plain
    {
        $domain   = config('authaction.domain');
        $audience = config('authaction.audience');
        $issuer   = "https://{$domain}";

        // Decode header to extract kid without full validation
        $parts  = explode('.', $token);
        $header = json_decode(base64_decode(strtr($parts[0] ?? '', '-_', '+/')), true) ?? [];
        $kid    = $header['kid'] ?? null;

        $pem    = $this->getPublicKey($domain, $kid);
        $config = $this->makeConfig($pem, $issuer, $audience);

        try {
            $parsed = $config->parser()->parse($token);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Invalid token: ' . $e->getMessage());
        }

        assert($parsed instanceof Plain);

        try {
            $config->validator()->assert($parsed, ...$config->validationConstraints());
        } catch (RequiredConstraintsViolated) {
            // Possible key rotation — bust cache and retry once
            Cache::forget("authaction_jwks_{$domain}");
            $pem    = $this->getPublicKey($domain, $kid);
            $config = $this->makeConfig($pem, $issuer, $audience);
            $config->validator()->assert($parsed, ...$config->validationConstraints());
        }

        return $parsed;
    }

    private function makeConfig(string $pem, string $issuer, string $audience): Configuration
    {
        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(''),
            InMemory::plainText($pem)
        );

        $config->setValidationConstraints(
            new SignedWith($config->signer(), $config->verificationKey()),
            new IssuedBy($issuer),
            new PermittedFor($audience),
            new StrictValidAt(SystemClock::fromSystemTimezone()),
        );

        return $config;
    }

    private function getPublicKey(string $domain, ?string $kid): string
    {
        $keys = Cache::remember("authaction_jwks_{$domain}", ttl: 3600, callback: function () use ($domain) {
            $response = Http::get("https://{$domain}/.well-known/jwks.json");
            $response->throw();
            return $response->json('keys', []);
        });

        foreach ($keys as $key) {
            if ($kid === null || ($key['kid'] ?? null) === $kid) {
                return $this->jwkToPem($key);
            }
        }

        throw new \RuntimeException('Matching public key not found');
    }

    // Converts a JWK (n, e components) to a PEM-encoded RSA public key
    // using raw ASN.1 DER encoding — no extra dependencies required.
    private function jwkToPem(array $jwk): string
    {
        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        if (ord($n[0]) > 0x7f) $n = "\x00" . $n;
        if (ord($e[0]) > 0x7f) $e = "\x00" . $e;

        $rsaKey = $this->asn1Seq($this->asn1Int($n) . $this->asn1Int($e));
        $spki   = $this->asn1Seq(
            $this->asn1Seq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00") .
            $this->asn1BitStr("\x00" . $rsaKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
    }

    private function asn1Len(int $len): string
    {
        if ($len < 128) return chr($len);
        $bytes = '';
        while ($len > 0) { $bytes = chr($len & 0xff) . $bytes; $len >>= 8; }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private function asn1Int(string $bytes): string    { return "\x02" . $this->asn1Len(strlen($bytes)) . $bytes; }
    private function asn1Seq(string $bytes): string    { return "\x30" . $this->asn1Len(strlen($bytes)) . $bytes; }
    private function asn1BitStr(string $bytes): string { return "\x03" . $this->asn1Len(strlen($bytes)) . $bytes; }
}
