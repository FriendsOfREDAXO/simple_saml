<?php

namespace LightSaml\Credential;

use RobRichards\XMLSecLibs\XMLSecurityKey;

class X509Credential extends AbstractCredential implements X509CredentialInterface
{
    /** @var X509Certificate */
    protected $certificate;

    /**
     * @param XMLSecurityKey $privateKey
     */
    public function __construct(X509Certificate $certificate, XMLSecurityKey $privateKey = null)
    {
        parent::__construct();
        $this->certificate = $certificate;

        $this->setPublicKey(KeyHelper::createPublicKey($certificate));

        $this->setKeyNames([$this->getCertificate()->getName()]);

        if ($privateKey) {
            $this->setPrivateKey($privateKey);
        }
    }

    /**
     * @return X509Certificate
     */
    public function getCertificate()
    {
        return $this->certificate;
    }
}
