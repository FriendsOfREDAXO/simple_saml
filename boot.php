<?php

// TODOS:
// Cert vom SP testen beachten ? .. Damit das auch klappt ..
// Verwaltung bauen oder doch lieber programatisch ?
// Logout Link bauen (mit returnTo und ohne??)
// NameIDFormat aus Metas noch beachtem
// Active Directory Federation Services (ADFS)
// - am Beispiel Nextcloud: https://portal.nextcloud.com/article/configuring-single-sign-on-10.html

// SSO auch mit entityKey
// SLO auch einbauen.
// Metadata anzeigen - Info ob private und certificate matchen

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
