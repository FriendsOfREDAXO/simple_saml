<?php

namespace REDAXO\Simple_SAML\Modules;

use GuzzleHttp\Psr7\ServerRequest;
use REDAXO\Simple_SAML\Simple_SAML;

abstract class AbstractModule
{
    public static $key = 'default';

    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    public function addData($data)
    {
        $this->data = $data;
    }

    public function getEntityUrl()
    {
        return ServerRequest::fromGlobals()->getUri()->getScheme().'://'.ServerRequest::fromGlobals()->getUri()->getHost().'/'.Simple_SAML::$basePath.'/'.Simple_SAML::$metadataPath.'/'.$this->getIdentifier();
    }

    public function getSSOUrl()
    {
        return ServerRequest::fromGlobals()->getUri()->getScheme().'://'.ServerRequest::fromGlobals()->getUri()->getHost().'/'.Simple_SAML::$basePath.'/'.Simple_SAML::$ssoPath.'/'.$this->getIdentifier();
    }

    public function getSLOUrl()
    {
        return ServerRequest::fromGlobals()->getUri()->getScheme().'://'.ServerRequest::fromGlobals()->getUri()->getHost().'/'.Simple_SAML::$basePath.'/'.Simple_SAML::$sloPath.'/'.$this->getIdentifier();
    }

    public function getsingleSignOnServiceBinding()
    {
        // TODO: dynamisch auslesen - Varianten anbieten ?
        return 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    }

    public function getsingleSignOutServiceBinding()
    {
        // TODO: noch nicht eingebaut
        return 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    }

    abstract public function getCertificate();

    abstract public function getPrivateKey();

    abstract public function getClaimValue(string $claim);

    abstract public function getSubject(string $format, \LightSaml\Model\Protocol\NameIDPolicy $NameIDPolicy);

    public function getIdentifier()
    {
        return $this->data['entityId'];
    }

    public function getKey()
    {
        return static::$key;
    }

    abstract public function authenticate(string $SAMLRequest, string $RelayState);

    abstract public function isAuthenticated();
}
