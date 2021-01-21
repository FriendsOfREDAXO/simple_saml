<?php

if (rex::isFrontend()) {
    \REDAXO\Simple_SAML\Modules\Modules::setModule(new \REDAXO\Simple_SAML\Modules\YCom());

    rex_extension::register(
        'PACKAGES_INCLUDED',
        static function ($params) {
            $SL = \REDAXO\Simple_SAML\Simple_SAML::factory()->init();
        },
        rex_extension::LATE
    );
}
