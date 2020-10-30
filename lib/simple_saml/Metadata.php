<?php

namespace REDAXO\Simple_SAML;

use LightSaml\ClaimTypes;
use LightSaml\SamlConstants;

class Metadata
{
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

    // TODO:
    public function getSingleLogoutServiceURL()
    {
        return $this->data['singleLogoutService']['url'];
    }

    public function getClaims()
    {
        return $this->data['Claims'] ?? [ClaimTypes::EMAIL_ADDRESS, ClaimTypes::COMMON_NAME];
    }

    public function getIssuer()
    {
        return $this->getIdp()->getIdentifier();
    }

    public static function addMetadata($metadata)
    {
        self::$metadata[] = $metadata;
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
