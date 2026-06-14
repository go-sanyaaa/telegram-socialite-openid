<?php

namespace SocialiteProviders\TelegramOpenId\Tests;

use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('services.telegram', [
            'client_id' => '123456789',
            'client_secret' => 'telegram-secret',
            'redirect' => 'https://example.com/auth/telegram/callback',
            'issuer' => 'https://oauth.telegram.org',
            'jwks_uri' => 'https://oauth.telegram.org/.well-known/jwks.json',
        ]);
    }
}
