<?php

namespace SocialiteProviders\TelegramOpenId;

use SocialiteProviders\Manager\SocialiteWasCalled;

class TelegramOpenIdExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('telegram', Provider::class);
    }
}
