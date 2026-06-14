<?php

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use SocialiteProviders\Manager\SocialiteWasCalled;
use SocialiteProviders\TelegramOpenId\Exceptions\InvalidTelegramIdToken;
use SocialiteProviders\TelegramOpenId\Exceptions\MissingIdToken;
use SocialiteProviders\TelegramOpenId\Exceptions\UnsupportedToken;
use SocialiteProviders\TelegramOpenId\Provider;
use SocialiteProviders\TelegramOpenId\TelegramIdTokenVerifier;
use SocialiteProviders\TelegramOpenId\TelegramOpenIdExtendSocialite;

it('registers the telegram socialite driver through the manager event', function () {
    $event = Mockery::mock(SocialiteWasCalled::class);
    $event->shouldReceive('extendSocialite')->once()->with('telegram', Provider::class);

    (new TelegramOpenIdExtendSocialite)->handle($event);
});

it('redirects to Telegram with state, openid scope, and PKCE', function () {
    $request = makeRequest('/redirect');
    $provider = makeProvider($request);

    $response = $provider->redirect();
    $location = $response->headers->get('Location');
    $query = parse_url_query($location);

    expect(parse_url($location, PHP_URL_SCHEME))->toBe('https')
        ->and(parse_url($location, PHP_URL_HOST))->toBe('oauth.telegram.org')
        ->and(parse_url($location, PHP_URL_PATH))->toBe('/auth')
        ->and($query['client_id'])->toBe('123456789')
        ->and($query['redirect_uri'])->toBe('https://example.com/auth/telegram/callback')
        ->and($query['response_type'])->toBe('code')
        ->and($query['scope'])->toBe('openid')
        ->and($query['state'])->toBeString()->not->toBeEmpty()
        ->and($query['code_challenge'])->toBeString()->not->toBeEmpty()
        ->and($query['code_challenge_method'])->toBe('S256');

    expect($request->session()->get('state'))->toBe($query['state'])
        ->and($request->session()->get('code_verifier'))->toBeString()->not->toBeEmpty();
});

it('can expand Telegram scopes explicitly', function () {
    $provider = makeProvider();

    $location = $provider->scopes(['profile', 'phone', 'telegram:bot_access'])->redirect()->headers->get('Location');
    $query = parse_url_query($location);

    expect(explode(' ', $query['scope']))->toBe(['openid', 'profile', 'phone', 'telegram:bot_access']);
});

it('exchanges authorization codes with basic auth and the PKCE verifier', function () {
    $history = [];
    $mock = new MockHandler([
        new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'access-token'])),
    ]);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    $request = makeRequest('/callback', [
        'code' => 'authorization-code',
    ]);
    $provider = makeProvider(request: $request);
    $request->session()->put('code_verifier', 'stored-code-verifier');
    $provider->setHttpClient(new Client(['handler' => $stack]));

    $provider->getAccessTokenResponse('authorization-code');

    $request = $history[0]['request'];
    parse_str((string) $request->getBody(), $form);

    expect((string) $request->getUri())->toBe(Provider::TOKEN_URL)
        ->and($request->getHeaderLine('Authorization'))->toBe('Basic '.base64_encode('123456789:telegram-secret'))
        ->and($form)->toMatchArray([
            'grant_type' => 'authorization_code',
            'client_id' => '123456789',
            'code' => 'authorization-code',
            'redirect_uri' => 'https://example.com/auth/telegram/callback',
            'code_verifier' => 'stored-code-verifier',
        ])
        ->and($form)->not->toHaveKey('client_secret');
});

it('maps verified Telegram ID token claims to a Socialite user', function () {
    [$privateKey, $jwks] = rsaSigningFixture();
    $idToken = telegramIdToken($privateKey, [
        'sub' => '1234123412341234123',
        'name' => 'Ada Lovelace',
        'preferred_username' => 'ada',
        'picture' => 'https://cdn.example.com/avatar.jpg',
    ]);

    Http::fake([
        TelegramIdTokenVerifier::DEFAULT_JWKS_URI => Http::response($jwks),
    ]);

    $provider = makeCallbackProvider([
        'access_token' => 'telegram-access-token',
        'expires_in' => 3600,
        'id_token' => $idToken,
    ]);

    $user = $provider->user();

    expect($user->getId())->toBe('1234123412341234123')
        ->and($user->getNickname())->toBe('ada')
        ->and($user->getName())->toBe('Ada Lovelace')
        ->and($user->getEmail())->toBeNull()
        ->and($user->getAvatar())->toBe('https://cdn.example.com/avatar.jpg')
        ->and($user->token)->toBe('telegram-access-token')
        ->and($user->expiresIn)->toBe(3600)
        ->and($user->user['sub'])->toBe('1234123412341234123');

    $cached = Cache::get(TelegramIdTokenVerifier::CACHE_KEY_PREFIX.sha1(TelegramIdTokenVerifier::DEFAULT_JWKS_URI));

    expect($cached)->toBe($jwks)
        ->and($cached['keys'][0]['n'])->toBeString()
        ->and($cached['keys'][0])->not->toHaveKey('key');
});

it('requires an id token in the token response', function () {
    $provider = makeCallbackProvider([
        'access_token' => 'telegram-access-token',
    ]);

    expect(fn () => $provider->user())->toThrow(MissingIdToken::class);
});

it('rejects invalid Telegram token signatures', function () {
    [$privateKey] = rsaSigningFixture('signing-key');
    [, $jwks] = rsaSigningFixture('different-key');

    Http::fake([
        TelegramIdTokenVerifier::DEFAULT_JWKS_URI => Http::response($jwks),
    ]);

    $provider = makeCallbackProvider([
        'access_token' => 'telegram-access-token',
        'id_token' => telegramIdToken($privateKey, kid: 'signing-key'),
    ]);

    expect(fn () => $provider->user())->toThrow(InvalidTelegramIdToken::class);
});

it('rejects invalid issuer, audience, and missing subject claims', function (array $override) {
    [$privateKey, $jwks] = rsaSigningFixture();

    Http::fake([
        TelegramIdTokenVerifier::DEFAULT_JWKS_URI => Http::response($jwks),
    ]);

    $provider = makeCallbackProvider([
        'access_token' => 'telegram-access-token',
        'id_token' => telegramIdToken($privateKey, $override),
    ]);

    expect(fn () => $provider->user())->toThrow(InvalidTelegramIdToken::class);
})->with([
    'invalid issuer' => [['iss' => 'https://example.com']],
    'invalid audience' => [['aud' => '987654321']],
    'missing subject' => [['sub' => null]],
]);

it('requires HTTPS for the JWKS URI', function () {
    [$privateKey] = rsaSigningFixture();

    $provider = makeCallbackProvider([
        'access_token' => 'telegram-access-token',
        'id_token' => telegramIdToken($privateKey),
    ], [
        'jwks_uri' => 'http://oauth.telegram.org/.well-known/jwks.json',
    ]);

    expect(fn () => $provider->user())->toThrow(InvalidTelegramIdToken::class);
});

it('does not support userFromToken because Telegram has no UserInfo endpoint', function () {
    $provider = makeProvider();

    expect(fn () => $provider->userFromToken('access-token'))->toThrow(UnsupportedToken::class);
});

function makeCallbackProvider(array $tokenResponse, array $configOverrides = []): Provider
{
    $state = 'known-state';
    $request = makeRequest('/callback', [
        'code' => 'authorization-code',
        'state' => $state,
    ]);
    $request->session()->put('state', $state);
    $request->session()->put('code_verifier', 'stored-code-verifier');

    $provider = makeProvider($request, $configOverrides);
    $provider->setHttpClient(new Client([
        'handler' => new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], json_encode($tokenResponse)),
        ]),
    ]));

    return $provider;
}

function makeProvider(?Request $request = null, array $configOverrides = []): Provider
{
    $provider = new Provider(
        $request ?: makeRequest('/redirect'),
        '123456789',
        'telegram-secret',
        'https://example.com/auth/telegram/callback',
    );

    $provider->setConfig(new SocialiteProviders\Manager\Config(
        '123456789',
        'telegram-secret',
        'https://example.com/auth/telegram/callback',
        array_merge([
            'issuer' => TelegramIdTokenVerifier::DEFAULT_ISSUER,
            'jwks_uri' => TelegramIdTokenVerifier::DEFAULT_JWKS_URI,
        ], $configOverrides),
    ));

    return $provider;
}

function makeRequest(string $uri, array $query = []): Request
{
    $request = Request::create($uri, 'GET', $query);
    $request->setLaravelSession(new Store('array', new ArraySessionHandler(120)));

    return $request;
}

function parse_url_query(string $url): array
{
    parse_str(parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}

function rsaSigningFixture(string $kid = 'test-key'): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    openssl_pkey_export($resource, $privateKey);
    $details = openssl_pkey_get_details($resource);

    return [
        $privateKey,
        [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'kid' => $kid,
                    'alg' => 'RS256',
                    'n' => base64url_encode($details['rsa']['n']),
                    'e' => base64url_encode($details['rsa']['e']),
                ],
            ],
        ],
    ];
}

function telegramIdToken(string $privateKey, array $claims = [], string $kid = 'test-key'): string
{
    return JWT::encode(array_merge([
        'iss' => TelegramIdTokenVerifier::DEFAULT_ISSUER,
        'aud' => '123456789',
        'sub' => '1234123412341234123',
        'iat' => time(),
        'exp' => time() + 3600,
    ], $claims), $privateKey, 'RS256', $kid);
}

function base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}
