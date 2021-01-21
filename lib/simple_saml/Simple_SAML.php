<?php

declare(strict_types=1);

namespace REDAXO\Simple_SAML;

use DateTime;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\AudienceRestriction;
use LightSaml\Model\Assertion\AuthnContext;
use LightSaml\Model\Assertion\AuthnStatement;
use LightSaml\Model\Assertion\Conditions;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Assertion\SubjectConfirmation;
use LightSaml\Model\Assertion\SubjectConfirmationData;
use LightSaml\Model\Context\DeserializationContext;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Metadata\SingleSignOnService;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\Model\XmlDSig\SignatureStringReader;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use REDAXO\Simple_SAML\Modules\AbstractModule;
use rex_logger;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Simple_SAML
{
    /** @var ServerRequest */
    public static $request = null;
    public static $basePath = 'saml';
    public static $metadataPath = 'metadata';
    public static $sloPath = 'slo';
    public static $slsPath = 'sls';
    public static $ssoPath = 'sso';
    public static $funcPaths = ['metadata', 'slo', 'sls', 'sso'];
    public $SAMLRequest;
    public $RelayState;
    /** @var Metadata $this->Metadata */
    public $Metadata;
    /** @var AbstractModule $this->Idp */
    public $Idp;

    public static function factory()
    {
        return new self();
    }

    public function init()
    {
        self::$request = ServerRequest::fromGlobals();
        $currentPathAsArray = explode('/', self::$request->getUri()->getPath());
        if (!isset($currentPathAsArray[1]) || $currentPathAsArray[1] != self::$basePath ||
            !\in_array($currentPathAsArray[2], self::$funcPaths, true) || !isset($currentPathAsArray[2]) ||
            !isset($currentPathAsArray[3]) || '' == $currentPathAsArray[3]
        ) {
            return false;
        }

        $this->SAMLRequest = rex_request('SAMLRequest', 'string', null);
        $this->RelayState = rex_request('RelayState', 'string', null);

        try {
            /* @var Metadata $Metadata */
            $this->Metadata = Metadata::getByIdp($currentPathAsArray[3]);

            if (!$this->Metadata) {
                throw new \Exception('Metadata not found');
            }

            $this->Idp = $this->Metadata->getIdp();
            if (!$this->Idp) {
                throw new \Exception('Identity Provider Module not found');
            }

            switch ($currentPathAsArray[2]) {
                case self::$sloPath: // TODO: init Logout processs with returnTo or redirect from idp
                case self::$slsPath: // TODO: process Logout without returnTo
                    if ($this->SAMLRequest) {
                        echo $this->handleSAMLLogoutRequest();
                    }

                    break;
                case self::$metadataPath:
                    echo $this->getEntityDescriptor();

                    break;
                case self::$ssoPath:
                    if ($this->SAMLRequest) {
                        echo $this->handleSAMLLoginRequest();
                    }

                    break;
            }
            exit;
        } catch (\Exception $e) {
            rex_logger::logException($e);

            exit;
        }
    }

    protected function getEntityDescriptor()
    {
        // https://www.lightsaml.com/LightSAML-Core/Cookbook/How-to-make-entity-descriptor/

        $entityDescriptor = new \LightSaml\Model\Metadata\EntityDescriptor();
        $entityDescriptor
            ->setID(\LightSaml\Helper::generateID())
            ->setEntityID($this->Idp->getEntityUrl())
        ;

        $entityDescriptor->addItem(
            $IpdSsoDescriptor = (new \LightSaml\Model\Metadata\IdpSsoDescriptor())
        );

        $IpdSsoDescriptor->addKeyDescriptor(
            $keyDescriptor = (new \LightSaml\Model\Metadata\KeyDescriptor())
                ->setUse(\LightSaml\Model\Metadata\KeyDescriptor::USE_SIGNING)
                ->setCertificate($this->Idp->getCertificate())
        );

        $IpdSsoDescriptor->addSingleLogoutService(
            $keyDescriptor = (new SingleLogoutService())
                ->setLocation($this->Idp->getSLOUrl())
                ->setBinding($this->Idp->getsingleSignOutServiceBinding())
        );

        $IpdSsoDescriptor->addSingleSignOnService(
            $keyDescriptor = (new SingleSignOnService())
                ->setLocation($this->Idp->getSSOUrl())
                ->setBinding($this->Idp->getsingleSignOnServiceBinding())
        );

        // TODO: NameIdFormat

        $serializationContext = new SerializationContext();
        $document = $serializationContext->getDocument();
        $entityDescriptor->serialize($document, $serializationContext);

        header('Content-Type: text/xml');

        return $document->saveXML();
    }

    protected function handleSAMLLogoutRequest()
    {
        $decoded = base64_decode($this->SAMLRequest, true);
        $xml = gzinflate($decoded);

        $deserializationContext = new DeserializationContext();
        $deserializationContext->getDocument()->loadXML($xml);

        // $xml = str_replace(">", ">\n", ($xml)); echo "<br /><br />".nl2br(htmlspecialchars($xml));

        // TODO:
        // Logout User .. assertion auslesen udn ausloggen
        // slo, sls / mit returnTo und Ohne beachten.

        $logoutStatus = $this->Idp->logoutUser($this);

        $LogoutRequest = new LogoutRequest();
        $LogoutRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        // dump($this->SAMLRequest); dump($LogoutRequest);

        $response = new LogoutResponse();
        $response
            ->setRelayState($LogoutRequest->getRelayState())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setDestination($this->Metadata->getSingleLogoutServiceURL()) // TODO: ?
            ->setInResponseTo($LogoutRequest->getID())
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new Issuer($this->Metadata->getIssuer()))
            ->setSignature(new SignatureWriter($this->Idp->getCertificate(), $this->Idp->getPrivateKey()));

        // dump($response);

        $bindingFactory = new BindingFactory();
        $binding = $bindingFactory->create($this->Metadata->getSingleLogoutServiceBinding());

        $messageContext = new MessageContext();
        $messageContext->setBindingType($this->Metadata->getSingleLogoutServiceBinding());
        $messageContext->setMessage($response)->asResponse();

        /** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
        $httpResponse = $binding->send($messageContext);

        // dump($httpResponse); exit;

        return $httpResponse->getContent()."\n\n";
    }

    protected function handleSAMLLoginRequest()
    {

        $decoded = base64_decode($this->SAMLRequest, true);
        $xml = gzinflate($decoded);

        $deserializationContext = new DeserializationContext();
        $deserializationContext->getDocument()->loadXML($xml);

        $authnRequest = new AuthnRequest();
        $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        if (!$this->Idp) {
            throw new Exception('Identify Provider Module not found');
        }

        // Check Request Signature
        if ($this->Metadata->getSignMetadata()) {
            $SpCert = $this->Metadata->getCertificate();

            /** @var XMLSecurityKey $SPXmlSecurityKey */
            $SPXmlSecurityKey = KeyHelper::createPublicKey($SpCert);

            $SigAlgString = \rex_request::get('SigAlg', 'string', null);
            $SignatureString = \rex_request::get('Signature', 'string', null);

            $msg = [];
            foreach ($_REQUEST as $k => $r) {
                if ('Signature' != $k) {
                    $msg[] = $k.'='.urlencode($r);
                }
            }
            $msg = implode('&', $msg);

            $b = new SignatureStringReader($SignatureString, $SigAlgString, $msg);
            $b->validate($SPXmlSecurityKey);
        }

        if (!$this->Idp->isAuthenticated()) {
            $this->Idp->authenticate($this->SAMLRequest, $this->RelayState);
        }

        $response = new Response();
        $response
            ->addAssertion($assertion = new Assertion())
            ->setID(Helper::generateID())
            ->setInResponseTo($authnRequest->getId())
            ->setIssueInstant(new DateTime())
            ->setDestination($this->Metadata->getAssertionConsumerServiceURL())
            ->setIssuer(new Issuer($this->Metadata->getIssuer()))
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setSignature(new SignatureWriter($this->Idp->getCertificate(), $this->Idp->getPrivateKey()));

        if ($this->RelayState) {
            $response
                ->setRelayState($this->RelayState);
        }

        /** @var Subject $subject */
        $subject = $this->Idp->getSubject($this->Metadata->getNameIDFormat(), $authnRequest->getNameIDPolicy());

        $AttributeStatement = new AttributeStatement();

        foreach ($this->Metadata->getClaims() as $ClaimType) {
            if ($value = $this->Idp->getClaimValue($ClaimType)) {
                $AttributeStatement->addAttribute(new Attribute(
                    $ClaimType,
                    $value
                ));
            }
        }

        $assertion
            ->setId(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setIssuer(new Issuer($this->Metadata->getIssuer()))
            ->setSubject(
                    $subject
                    ->addSubjectConfirmation(
                        (new SubjectConfirmation())
                            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new SubjectConfirmationData())
                                    ->setInResponseTo($authnRequest->getId())
                                    ->setNotOnOrAfter(new DateTime('+1 MINUTE'))
                                    ->setRecipient($this->Metadata->getAssertionConsumerServiceURL()) // was: getIdentifier()
                            )
                    )
            )
            ->setConditions(
                (new Conditions())
                    ->setNotBefore(new DateTime())
                    ->setNotOnOrAfter(new DateTime('+2 HOURS'))
                    ->addItem(
                        new AudienceRestriction([$this->Metadata->getIdentifier()]) // getAssertionConsumerServiceURL()])
                    )
            )
            ->addItem(
                $AttributeStatement
            )
            ->addItem(
                (new AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
//                     ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new AuthnContext())
                            ->setAuthnContextClassRef(SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;

        $bindingFactory = new BindingFactory();
        $postBinding = $bindingFactory->create($this->Metadata->getAssertionConsumerServiceBinding());
        $messageContext = new MessageContext();
        $messageContext->setMessage($response)->asResponse();

        /** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
        $httpResponse = $postBinding->send($messageContext);

        return $httpResponse->getContent()."\n\n";
    }
}
