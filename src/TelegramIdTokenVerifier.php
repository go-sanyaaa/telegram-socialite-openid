<?php

namespace SocialiteProviders\TelegramOpenId;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use SocialiteProviders\TelegramOpenId\Exceptions\InvalidTelegramIdToken;
use Throwable;

class TelegramIdTokenVerifier
{
    public const DEFAULT_ISSUER = 'https://oauth.telegram.org';

    public const DEFAULT_JWKS_URI = 'https://oauth.telegram.org/.well-known/jwks.json';

    public const CACHE_KEY_PREFIX = 'socialiteproviders.telegram-openid.jwks.';

    /**
     * @return array<string, mixed>
     */
    public function verify(
        string $idToken,
        string $clientId,
        ?string $issuer = null,
        ?string $jwksUri = null,
        string|array|null $proxy = null,
    ): array {
        $issuer = $issuer ?: self::DEFAULT_ISSUER;
        $jwksUri = $jwksUri ?: self::DEFAULT_JWKS_URI;

        $this->ensureSecureJwksUri($jwksUri);

        try {
            $decoded = JWT::decode($idToken, JWK::parseKeySet($this->getJwks($jwksUri, $proxy)));
        } catch (Throwable $exception) {
            throw new InvalidTelegramIdToken('The Telegram ID token signature could not be verified.', 0, $exception);
        }

        $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($claims)) {
            throw new InvalidTelegramIdToken('The Telegram ID token payload is invalid.');
        }

        $this->validateClaims($claims, $clientId, $issuer);

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    protected function getJwks(string $jwksUri, string|array|null $proxy = null): array
    {
        $jwks = Cache::remember($this->cacheKey($jwksUri), now()->addHour(), function () use ($jwksUri, $proxy): array {
            $request = Http::acceptJson();

            if ($proxy) {
                $request = $request->withOptions(['proxy' => $proxy]);
            }

            $payload = $request->get($jwksUri)->throw()->json();

            if (! is_array($payload)) {
                throw new InvalidTelegramIdToken('The Telegram JWKS endpoint returned an invalid payload.');
            }

            return $payload;
        });

        if (! is_array($jwks)) {
            throw new InvalidTelegramIdToken('The cached Telegram JWKS payload is invalid.');
        }

        return $jwks;
    }

    protected function cacheKey(string $jwksUri): string
    {
        return self::CACHE_KEY_PREFIX.sha1($jwksUri);
    }

    protected function ensureSecureJwksUri(string $jwksUri): void
    {
        if (parse_url($jwksUri, PHP_URL_SCHEME) !== 'https') {
            throw new InvalidTelegramIdToken('The Telegram JWKS URI must use HTTPS.');
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function validateClaims(array $claims, string $clientId, string $issuer): void
    {
        if (($claims['iss'] ?? null) !== $issuer) {
            throw new InvalidTelegramIdToken('The Telegram ID token issuer is invalid.');
        }

        $audiences = (array) ($claims['aud'] ?? []);

        if (! in_array((string) $clientId, array_map('strval', $audiences), true)) {
            throw new InvalidTelegramIdToken('The Telegram ID token audience is invalid.');
        }

        if (empty($claims['sub']) || ! is_scalar($claims['sub'])) {
            throw new InvalidTelegramIdToken('The Telegram ID token subject is missing.');
        }
    }
}
