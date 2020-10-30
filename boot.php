<?php

// TODOS:
// Diverse SAML SP einrichten .. Festlegen
// Cert vom SP testen und Idp .. Damit das auch klappt ..

// Claims zuweisbar machen
// http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
// http://schemas.xmlsoap.org/claims/CommonName
// Verwaltung bauen
// Logout Link bauen (mit returnTo und ohne??)
// NameIDFormat aus Metas noch beachtem
// Active Directory Federation Services (ADFS)
// - am Beispiel Nextcloud: https://portal.nextcloud.com/article/configuring-single-sign-on-10.html

// Description anpassen
// SSO auch mit entityKey
// SLO auch einbauen.

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
