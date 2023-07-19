<?php

namespace REDAXO\Simple_SAML\Modules;

use GuzzleHttp\Psr7\ServerRequest;
use REDAXO\Simple_SAML\Simple_SAML;

abstract class AbstractModule
{
    /** @api */
    public static $key = 'default';

    /**
     * @var array
     */
    protected $data;

    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /** @api */
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

    /** @api */
    public function logoutUser(\REDAXO\Simple_SAML\Simple_SAML $simple_SAML)
    {
        return true;
    }

    abstract public function getCertificate();

    abstract public function getPrivateKey();

    /** @api */
    abstract public function getClaimValue(string $claim);

    /** @api */
    abstract public function getSubject(string $format, \LightSaml\Model\Protocol\NameIDPolicy $NameIDPolicy);

    public function getIdentifier()
    {
        return $this->data['entityId'];
    }

    public function getKey()
    {
        return static::$key;
    }

    /** @api */
    abstract public function authenticate(string $SAMLRequest, string $RelayState);

    /** @api */
    abstract public function isAuthenticated();
}
