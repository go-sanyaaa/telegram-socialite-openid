# Telegram OpenID Provider for Laravel Socialite

Telegram OpenID Connect provider for Laravel Socialite, implemented in the
`SocialiteProviders` style.

This package registers the `telegram` Socialite driver. It does not publish
routes, controllers, migrations, or user persistence code; each Laravel
application should decide how Telegram identities map to local users.

## Installation

```bash
composer require socialiteproviders/telegram-openid
```

Install and register the SocialiteProviders Manager as described in the
[SocialiteProviders usage guide](https://socialiteproviders.com/usage/).

For Laravel 11 and newer, register the listener in `AppServiceProvider`:

```php
use Illuminate\Support\Facades\Event;
use SocialiteProviders\Manager\SocialiteWasCalled;
use SocialiteProviders\TelegramOpenId\TelegramOpenIdExtendSocialite;

public function boot(): void
{
    Event::listen(function (SocialiteWasCalled $event): void {
        (new TelegramOpenIdExtendSocialite)->handle($event);
    });
}
```

For Laravel 10, add the listener to `EventServiceProvider`:

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        \SocialiteProviders\TelegramOpenId\TelegramOpenIdExtendSocialite::class.'@handle',
    ],
];
```

## Configuration

Add a `telegram` entry to `config/services.php`:

```php
'telegram' => [
    'client_id' => env('TELEGRAM_CLIENT_ID'),
    'client_secret' => env('TELEGRAM_CLIENT_SECRET'),
    'redirect' => env('TELEGRAM_REDIRECT_URI'),
    'issuer' => env('TELEGRAM_ISSUER', 'https://oauth.telegram.org'),
    'jwks_uri' => env('TELEGRAM_JWKS_URI', 'https://oauth.telegram.org/.well-known/jwks.json'),
    'proxy' => env('TELEGRAM_PROXY'),
    'timeout' => env('TELEGRAM_TIMEOUT', 5),
    'connect_timeout' => env('TELEGRAM_CONNECT_TIMEOUT', 3),
],
```

Then set the matching environment variables:

```dotenv
TELEGRAM_CLIENT_ID=123456789
TELEGRAM_CLIENT_SECRET=your-client-secret
TELEGRAM_REDIRECT_URI=https://example.com/auth/telegram/callback
TELEGRAM_PROXY=http://127.0.0.1:8080
TELEGRAM_TIMEOUT=5
TELEGRAM_CONNECT_TIMEOUT=3
```

Create a Telegram bot and register your Allowed URLs in BotFather under
`Bot Settings > Web Login`. Telegram will only redirect to URLs registered
there. See the official [Telegram Login documentation](https://core.telegram.org/bots/telegram-login).

## Usage

Redirect users through Socialite as usual:

```php
use Laravel\Socialite\Facades\Socialite;

Route::get('/auth/telegram/redirect', function () {
    return Socialite::driver('telegram')->redirect();
});

Route::get('/auth/telegram/callback', function () {
    $telegramUser = Socialite::driver('telegram')->user();

    // $telegramUser->getId();
    // $telegramUser->getNickname();
    // $telegramUser->getName();
    // $telegramUser->getAvatar();
    // $telegramUser->getEmail(); // always null
});
```

The default scope is only `openid`. Request additional Telegram scopes
explicitly when needed:

```php
return Socialite::driver('telegram')
    ->scopes(['profile', 'phone', 'telegram:bot_access'])
    ->redirect();
```

Telegram returns user claims in the ID token and currently does not provide a
separate UserInfo endpoint. For that reason, `userFromToken()` is unsupported.

## Proxy

If your server must reach Telegram through an HTTP proxy, set `proxy` in the
`telegram` service config. The proxy is used for server-side requests to the
Telegram token endpoint and JWKS endpoint:

```php
'telegram' => [
    // ...
    'proxy' => env('TELEGRAM_PROXY'),
    'timeout' => env('TELEGRAM_TIMEOUT', 5),
    'connect_timeout' => env('TELEGRAM_CONNECT_TIMEOUT', 3),
],
```

The default server-side HTTP timeout is 5 seconds and the default connect
timeout is 3 seconds.

The browser redirect to `oauth.telegram.org/auth` is performed by the user's
browser and is not proxied by this PHP package.

## Returned User

The provider maps verified ID token claims as follows:

- `id`: `sub`
- `nickname`: `preferred_username`
- `name`: `name`, falling back to nickname and then `sub`
- `avatar`: `picture`
- `email`: always `null`
- raw claims: `$user->user`

The ID token signature is verified against Telegram JWKS and validates `iss`,
`aud`, expiration, and `sub`.

## References

- [Telegram Login / OpenID Connect](https://core.telegram.org/bots/telegram-login)
- [Laravel Socialite](https://laravel.com/docs/12.x/socialite)
- [SocialiteProviders usage](https://socialiteproviders.com/usage/)
