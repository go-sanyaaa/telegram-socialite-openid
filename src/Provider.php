<?php

namespace SocialiteProviders\TelegramOpenId;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use SocialiteProviders\TelegramOpenId\Exceptions\MissingIdToken;
use SocialiteProviders\TelegramOpenId\Exceptions\UnsupportedToken;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'TELEGRAM';

    public const AUTH_URL = 'https://oauth.telegram.org/auth';

    public const TOKEN_URL = 'https://oauth.telegram.org/token';

    /**
     * @var array<int, string>
     */
    protected $scopes = ['openid'];

    protected $scopeSeparator = ' ';

    protected $usesPKCE = true;

    /**
     * @var array<int, string>
     */
    protected static array $additionalConfigKeys = [
        'issuer',
        'jwks_uri',
        'proxy',
        'timeout',
        'connect_timeout',
    ];

    /**
     * @return array<int, string>
     */
    public static function additionalConfigKeys()
    {
        return static::$additionalConfigKeys;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(self::AUTH_URL, $state);
    }

    protected function getTokenUrl(): string
    {
        return self::TOKEN_URL;
    }

    public function getAccessTokenResponse($code)
    {
        $options = [
            RequestOptions::HEADERS => $this->getTokenHeaders($code),
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ];

        if ($proxy = $this->getConfig('proxy')) {
            $options[RequestOptions::PROXY] = $proxy;
        }

        $options[RequestOptions::TIMEOUT] = (float) $this->getConfig('timeout', 5);
        $options[RequestOptions::CONNECT_TIMEOUT] = (float) $this->getConfig('connect_timeout', 3);

        $response = $this->getHttpClient()->post($this->getTokenUrl(), $options);

        return json_decode($response->getBody(), true);
    }

    /**
     * @return array<string, string>
     */
    protected function getTokenHeaders($code): array
    {
        return [
            'Accept' => 'application/json',
            'Authorization' => 'Basic '.base64_encode($this->clientId.':'.$this->clientSecret),
        ];
    }

    /**
     * @return array<string, string|null>
     */
    protected function getTokenFields($code): array
    {
        $fields = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'code' => $code,
            'redirect_uri' => $this->redirectUrl,
        ];

        if ($this->usesPKCE()) {
            $fields['code_verifier'] = $this->request->session()->pull('code_verifier');
        }

        return array_merge($fields, $this->parameters);
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $claims = $this->getClaimsFromTokenResponse($response);

        $this->user = $this->mapUserToObject($claims);

        if ($this->user instanceof User) {
            $this->user->setAccessTokenResponseBody($response);
        }

        return $this->user
            ->setToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'))
            ->setApprovedScopes($this->parseApprovedScopes($response));
    }

    public function userFromToken($token)
    {
        throw new UnsupportedToken('Telegram does not provide a UserInfo endpoint; use the authorization callback ID token instead.');
    }

    protected function getUserByToken($token): array
    {
        throw new UnsupportedToken('Telegram does not provide a UserInfo endpoint; use the authorization callback ID token instead.');
    }

    protected function mapUserToObject(array $user): User
    {
        $nickname = Arr::get($user, 'preferred_username');

        return (new User)->setRaw($user)->map([
            'id' => (string) Arr::get($user, 'sub'),
            'nickname' => $nickname,
            'name' => Arr::get($user, 'name', $nickname ?: (string) Arr::get($user, 'sub')),
            'email' => null,
            'avatar' => Arr::get($user, 'picture'),
        ]);
    }

    /**
     * @param array<string, mixed> $response
     * @return array<string, mixed>
     */
    protected function getClaimsFromTokenResponse(array $response): array
    {
        $idToken = Arr::get($response, 'id_token');

        if (! is_string($idToken) || $idToken === '') {
            throw new MissingIdToken('The Telegram token response did not include an ID token.');
        }

        return (new TelegramIdTokenVerifier)->verify(
            $idToken,
            (string) $this->clientId,
            $this->getConfig('issuer', TelegramIdTokenVerifier::DEFAULT_ISSUER),
            $this->getConfig('jwks_uri', TelegramIdTokenVerifier::DEFAULT_JWKS_URI),
            $this->getConfig('proxy'),
            (float) $this->getConfig('timeout', 5),
            (float) $this->getConfig('connect_timeout', 3),
        );
    }
}
