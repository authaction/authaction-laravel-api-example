# authaction-laravel-api-example

A Laravel application demonstrating API authorization using [AuthAction](https://app.authaction.com/) with JWKS-based JWT validation.

## Overview

This application shows how to configure and handle authorization using AuthAction's access tokens in a Laravel API. It validates JSON Web Tokens (JWT) signed with RS256 by fetching public keys dynamically from AuthAction's JWKS endpoint via a custom middleware.

## Prerequisites

- **PHP 8.2+** and **Composer**
- **AuthAction credentials**: `tenantDomain` and `apiIdentifier` from your AuthAction account.

## Installation

1. **Clone the repository**:

   ```bash
   git clone git@github.com:authaction/authaction-laravel-api-example.git
   cd authaction-laravel-api-example
   ```

2. **Install dependencies**:

   ```bash
   composer install
   ```

3. **Configure your AuthAction credentials**:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and replace the placeholders:

   ```env
   AUTHACTION_DOMAIN=your-authaction-tenant-domain
   AUTHACTION_AUDIENCE=your-authaction-api-identifier
   ```

   `composer install` auto-generates `APP_KEY` via `php artisan key:generate`.

## Usage

1. **Start the development server**:

   ```bash
   php artisan serve
   ```

   The API will be available at `http://localhost:8000`.

2. **Obtain an access token** via client credentials:

   ```bash
   curl --request POST \
     --url https://your-authaction-tenant-domain/oauth2/m2m/token \
     --header 'content-type: application/json' \
     --data '{
       "client_id": "your-authaction-app-clientid",
       "client_secret": "your-authaction-app-client-secret",
       "audience": "your-authaction-api-identifier",
       "grant_type": "client_credentials"
     }'
   ```

3. **Call the public endpoint** (no token required):

   ```bash
   curl http://localhost:8000/public
   ```

   ```json
   { "message": "This is a public message!" }
   ```

4. **Call the protected endpoint** with the access token:

   ```bash
   curl --request GET \
     --url http://localhost:8000/protected \
     --header 'Authorization: Bearer YOUR_ACCESS_TOKEN'
   ```

   ```json
   { "message": "This is a protected message!", "sub": "client-id@clients" }
   ```

## Project Structure

```
authaction-laravel-api-example/
├── app/
│   └── Http/
│       └── Middleware/
│           └── AuthActionJWT.php    # JWKS fetching and JWT validation
├── bootstrap/
│   └── app.php                      # Registers auth.jwt middleware alias
├── config/
│   └── authaction.php               # Reads AUTHACTION_DOMAIN / AUDIENCE from .env
├── routes/
│   └── api.php                      # GET /public and GET /protected
├── .env.example
├── composer.json
└── README.md
```

## Code Explanation

### `app/Http/Middleware/AuthActionJWT.php` — JWT Validation

Equivalent to `JwtStrategy` in the NestJS example.

- **`getJwks()`** — Fetches public keys from
  `https://{AUTHACTION_DOMAIN}/.well-known/jwks.json` and caches them for
  1 hour using Laravel's Cache facade. On key rotation (kid not found), the
  cache is busted and the JWKS is re-fetched once before retrying decode.

- **`verifyToken()`** — Decodes and validates the JWT using:
  - `JWK::parseKeySet()` from `firebase/php-jwt` to build a kid-indexed key map
  - Algorithm: `RS256` (enforced by the JWKS key type)
  - Issuer: `https://{AUTHACTION_DOMAIN}` (validated manually)
  - Audience: `{AUTHACTION_AUDIENCE}` (validated manually)

- **`handle()`** — Extracts the `Bearer` token from the `Authorization` header,
  calls `verifyToken()`, and stores the decoded payload in
  `$request->attributes` under the key `jwt_payload`.

### `bootstrap/app.php` — Middleware Registration

Registers `AuthActionJWT` as the `auth.jwt` middleware alias using Laravel 11's
fluent `withMiddleware()` API.

### `routes/api.php` — Routes

- **`GET /public`** — No middleware, accessible without authentication.
- **`GET /protected`** — Protected by `->middleware('auth.jwt')`. The decoded
  JWT payload is available via `$request->attributes->get('jwt_payload')`.

### `config/authaction.php` — Configuration

Reads `AUTHACTION_DOMAIN` and `AUTHACTION_AUDIENCE` from the environment and
exposes them via `config('authaction.domain')` and `config('authaction.audience')`.

## Common Issues

**Invalid token errors** — Verify that `AUTHACTION_DOMAIN` and
`AUTHACTION_AUDIENCE` match the values in your AuthAction dashboard exactly.

**Public key fetching errors** — Check that your application can reach
`https://{AUTHACTION_DOMAIN}/.well-known/jwks.json`.

**Unauthorized access** — Ensure the `Authorization: Bearer <token>` header is
present and the token was issued for the correct audience.

## Contributing

Feel free to submit issues or pull requests if you encounter bugs or have suggestions for improvement!
