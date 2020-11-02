# REDAXO - SAML Identity Provider via YCom-AddOn

Über dieses AddOn können 3rd Party Applikationen die YCom als Identity Provider nutzen, so dass man keine weiteren Logins anlegen muss und die YCom als SingleSignOn Server verwendet werden kann.

Es wird die Bibliothek lightSAML genutzt: https://github.com/lightSAML/lightSAML

Dabei tauchen folgende Begriffe häufig auf die wichtig sind, um zu verstehen wie man das System richtig aufsetzt.

Es gibt wie Webseite, wir nennen die Service Provider, welche eine andere Webseite, den Identity Provider, nutzen möchte um z.B. Userdaten abzufragen oder Authentifizierungen prüfen zu können. Dabei vertraut der Service Provider auf den Identity Provider.

Der Identity Provider bekommt diese Anfrage, und leitet, in diesem Fall auf das YCom Login um, wenn der User noch nicht authentifiziert ist oder leitet wieder direkt zum Service Provider mit den gewünschten Daten (Claims) zurück um damit dann weiter arbeiten zu können.

## Installation und Einrichtung

Zunächst das AddOn installieren, z.B. über den Installer innerhalb von REDAXO.

Damit Service Provider und Identity Provider wissen was und wie sie kommunizieren wollen, müssen entsprechende Metadaten definiert und angemeldet werden.

Dies müssen in der Laufzeit verfügbar gemacht werdem, z.B. indem man in der addons/project/boot.php diese Informationen ablegt.

Hier ein Beispiel:

```
$metadata = [
    'entityId' => 'http://webseite_die_saml_nutzen_will.de/',
    'AssertionConsumerService' => [
        'url' => 'http://webseite_die_saml_nutzen_will.de/acs/',
        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ],
    'singleLogoutService' => [
        'url' => 'http://webseite_die_saml_nutzen_will.de/slo/',
        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    ],
    'signMetadata' => false, // default is false
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
//    'x509cert' => '',
    'idp' => [
        'AuthModule' => 'YCom', // Im Moment nur YCom möglich
        'entityId' => 'irgendeinekennungohneleerzeichen',
        'x509cert' => '-----BEGIN CERTIFICATE-----
MIICMjCCAZugAwIBAgIBADANBgkqhkiG9w0BAQ0FADA2MQswCQYDVQQGEwJkZTEP
MA0GA1UECAwGSGVzc2VuMQowCAYDVQQKDAFZMQowCAYDVQQDDAFZMB4XDTIwMTAy
ODA4MDMzNFoXDTIxMTAyODA4MDMzNFowNjELMAkGA1UEBhMCZGUxDzANBgNVBAgM
Bkhlc3NlbjEKMAgGA1UECgwBWTEKMAgGA1UEAwwBWTCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEA3B+lRxtlIDlRTdvB7wIqHDLz3CpS7u9Z0kck2wZJtVhDKwFe
9KQAWspooFNpq9gxOPfmGhUUnjyPXXjYyfiSRI1wU4cEXEZbOHdYwTArsMsM7hRZ
RKXLaD5XoWUnERCs9x6XRj623MFkfhQspyxn8dgOs05+tqVwv2dBY4jqkFECAwEA
AaNQME4wHQYDVR0OBBYEFM7mVZD87fXtR05QIVqu/17DqIIEMB8GA1UdIwQYMBaA
FM7mVZD87fXtR05QIVqu/17DqIIEMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEN
BQADgYEAMiZJfEJl7NmXad8KAQ23akGMu5UBOk9tArQEm/EnoB6X3dwHDezcUBBL
/BIGz9dcKVsJ8RqYttatNzhc1m/RkA1V2QZOeXrNh0ENcBhaQP+pGepHNVFpFDFB
T11UW+zlnyZpEZYKBOFTFsNtJTCIUOjowwCLD5xfPF9iFTe7vwM=
-----END CERTIFICATE-----',

        'privateKey' => '-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANwfpUcbZSA5UU3b
we8CKhwy89wqUu7vWdJHJNsGSbVYQysBXvSkAFrKaKBTaavYMTj35hoVFJ48j114
2Mn4kkSNcFOHBFxGWzh3WMEwK7DLDO4UWUSly2g+V6FlJxEQrPcel0Y+ttzBZH4U
LKcsZ/HYDrNOfralcL9nQWOI6pBRAgMBAAECgYEAp9WVHjdcDorFXBjvsD21P9T1
rGu02iszECpghoMv1g4bAIJGFT+qaY8k4QFYc8ceGLKjBkYGd3PzV7CZkr1tP1+Z
G0t+LUUEvSXzL6iwuK94f8RXa9vEwjoEsWy3kPKnIsqjgt3VZj3ZgB7sPSkGZFnq
Y6pvZAZOSIybfYYoIHUCQQDvoonSx1B1h8yJ8FLG/Rf6h3onONwcP9ifELGN68Ys
HZtFT7+C9/LJssicq4hP1qCBXUSYL8fWVBex48s71sXrAkEA6yf/UfVJe36Dq3Xw
IA1GHDCOMuCvbPr0SzIo/ihVWRygyuBo188kzlNqvO08CWchrmiIJP04kFdY0oV6
ag5HswJADseNjIxyb+1CNje2Q0OU2QTGCek92hgt+hGDgedKv6nLy8iRXTiBpuL5
8H+71oC8QX5JHsHDp3pkQ7py7GvgpQJAVwxjUy99mB1pGFt8HCFNxrmiqerKhYkQ
TZWv3wWHMomKbA9OQDUJ5uayKGWZR9HJggpn+2lROv1af/OxMPlASQJBAN1nz5Tj
ZohtZQmpmEfLhpDidGGyk/nB3FXtiXvIuHV0QbFJ5uh3rnKcPBxw7y9tzKfF1n/3
r7O1dVxVszLRxqg=
-----END PRIVATE KEY-----',

        'Claims' => [
            LightSaml\ClaimTypes::NAME,
            LightSaml\ClaimTypes::EMAIL_ADDRESS,
            LightSaml\ClaimTypes::SURNAME,
            LightSaml\ClaimTypes::GIVEN_NAME,
        ]
    ]
];
```

Und hierrüber werden diese Metadaten angemeldet

```
\REDAXO\Simple_Saml\Metadata::addMetadata(new \REDAXO\Simple_SAML\Metadata($metadata));
```

### Service Provider

Die Informationen des SP müssen hier eingetragen werden.

```
'entityId' => 'http://webseite_die_saml_nutzen_will.de/',
    'AssertionConsumerService' => [
        'url' => 'http://webseite_die_saml_nutzen_will.de/acs/',
        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ],
    'singleLogoutService' => [
        'url' => 'http://webseite_die_saml_nutzen_will.de/slo/',
        'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    ],
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',

```

### Identity Provider

Unterhalb des Array `'idp' => []` kommen die Informationen des Identity Providers.

``` 
'AuthModule' => 'YCom'
```

hier ist im Moment nur 'YCom' möglich und wird definiert, welche Authentifizierungsmethode innerhalb von REDAXO verwendet wird.

```
'entityId' => 'irgendeinekennungohneleerzeichen',
```

Das ist die Kennung welche individuell sein sollte. Dabei bitte keine Sonderzeichen und Leerzeichen verwenden,

Mit dem Publickey und dem Privatekey wird die Antwort des Identity Providers an den Service Provider verschlüsselt.
Diese müssen entsprechend erstellt und eingebunden werden. Auch wenn hier die Key einfach im Array eingetragen sind, empfiehlt es sich diese in Dateien auszulagern und hier nur den Inhalt der Dateien einzubinden.

Wie man so ein key pair erstellt wird hier genauer beschrieben: https://www.lightsaml.com/LightSAML-Core/Cookbook/How-to-generate-key-pair/

```
'x509cert' => '-----BEGIN CERTIFICATE----- .... -----END PRIVATE KEY-----'
```

```
'privateKey' => '-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----',
```

Die Claims definieren, welche Informationen der Identity Provider zurückgeben soll. Welche möglich sind, kann man im Modul YCom nachsehen. (in addons/simple_saml/lib/)

```
'Claims' => [
            LightSaml\ClaimTypes::NAME,
            LightSaml\ClaimTypes::EMAIL_ADDRESS,
            LightSaml\ClaimTypes::SURNAME,
            LightSaml\ClaimTypes::GIVEN_NAME,
        ]
```

Der Identity Provider funktioniert über folgende Domains

https://die_webseite_die_saml_anbietet.de/saml/sso/[IdpEntityId]
https://die_webseite_die_saml_anbietet.de/saml/metadata/[IdpEntityId]




