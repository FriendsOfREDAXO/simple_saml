<?php

namespace REDAXO\Simple_SAML;

use LightSaml\ClaimTypes;
use LightSaml\Credential\X509Certificate;
use LightSaml\SamlConstants;
use REDAXO\Simple_SAML\Modules\AbstractModule;

class Metadata
{
    /**
     * @var int
     */
    private static $metadata = [];
    private $data = [];

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function getIdentifier()
    {
        return $this->data['entityId'] ?? null;
    }

    public function getCertificate()
    {
        if (!isset($this->data['x509cert'])) {
            return null;
        }
        try {
            $cert = new X509Certificate();
            $cert->loadPem($this->data['x509cert']);
            return $cert;
        } catch (\Exception $e) {
            throw new \Exception('SAML SP Certificate Error '. $e->getMessage());
        }
    }

    public function getSignMetadata()
    {
        if (!isset($this->data['signMetadata'])) {
            return false;
        }
        return $this->data['signMetadata'] ? true : false;
    }

    public function getIdp()
    {
        $idpData = $this->data['idp'];
        $idp = "\REDAXO\Simple_SAML\Modules\\".$idpData['AuthModule'];
        $idpObject = new $idp();
        $idpObject->addData($idpData);
        return $idpObject;
    }

    public function getAssertionConsumerServiceURL()
    {
        return $this->data['AssertionConsumerService']['url'];
    }

    public function getAssertionConsumerServiceBinding()
    {
        if (SamlConstants::BINDING_SAML2_HTTP_POST != $this->data['AssertionConsumerService']['binding']) {
            throw new \Exception('Only '.SamlConstants::BINDING_SAML2_HTTP_POST.' is supported');
        }

        return SamlConstants::BINDING_SAML2_HTTP_POST;
    }

    public function getNameIDFormat()
    {
        if (!isset($this->data['NameIDFormat'])) {
            throw new \Exception('NameIDFormat in Metadata is missing');
        }

        return $this->data['NameIDFormat'];
    }

    public function getInfoArray()
    {
        /** @var AbstractModule $Idp */
        $Idp = $this->getIdp();

        /** @var X509Certificate $cert */
        $cert = $Idp->getCertificate();
        $x509cert = '';
        if ($cert) {
            $x509cert = $this->data['idp']['x509cert'];
        }
        $private = ($Idp->getPrivateKey()) ? 'exists' : 'missing';

        return [
            'Service Provider' => [
                'entityId' => $this->getIdentifier(),
                'AssertionConsumerServiceURL' => $this->getAssertionConsumerServiceURL(),
                'AssertionConsumerServiceBinding' => $this->getAssertionConsumerServiceBinding(),
                'NameIdFormat' => $this->getNameIDFormat(),
            ],
            'Identity Provider' => [
                'entityId' => $Idp->getEntityUrl(),
                'singleSignOnServiceURL' => $Idp->getSSOUrl(),
                'singleSignOnServiceBinding' => $Idp->getsingleSignOnServiceBinding(),
                'singleLogoutServiceURL' => $Idp->getSLOUrl(),
                'singleLogoutServiceBinding' => $Idp->getsingleSignOutServiceBinding(),
                'x509cert' => $x509cert,
                'privateKey' => $private,
            ],
            'Modul Informationen' => [
                'Modultyp' => $Idp->getKey(),
                'Claims' => implode("\n", $this->getClaims()),
            ],
        ];
    }

    // TODO:
    public function getSingleLogoutServiceURL()
    {
        return $this->data['singleLogoutService']['url'];
    }

    public function getClaims()
    {
        return $this->data['idp']['Claims'] ?? [ClaimTypes::EMAIL_ADDRESS, ClaimTypes::COMMON_NAME];
    }

    public function getIssuer()
    {
        return $this->getIdp()->getEntityUrl();
    }

    public static function addMetadata($metadata)
    {
        self::$metadata[] = $metadata;
    }

    public static function getAll()
    {
        return self::$metadata;
    }

    public static function get(string $identifier)
    {
        // try via identifier
        foreach (self::$metadata as $md) {
            if ($identifier == $md->getIdentifier()) {
                return $md;
            }
        }
        throw new \Exception('Service Provider not found with this identifier '. $identifier);
    }

    public static function getByIdp(string $identifier)
    {
        // try via identifier
        foreach (self::$metadata as $md) {
            if ($identifier == $md->getIdp()->getIdentifier()) {
                return $md;
            }
        }
        throw new \Exception('Identity Provider not found with this identifier '. $identifier);
    }
}
