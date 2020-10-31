<?php

namespace REDAXO\Simple_SAML;

use DateTime;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
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
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use REDAXO\Simple_SAML\Modules\AbstractModule;

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
            !\in_array($currentPathAsArray[2], self::$funcPaths) || !isset($currentPathAsArray[2]) ||
            !isset($currentPathAsArray[3]) || '' == $currentPathAsArray[3]
        ) {
            return false;
        }

        $this->SAMLRequest = rex_request('SAMLRequest', 'string', null);
        $this->RelayState = rex_request('RelayState', 'string', null);

        /** @var Metadata $Metadata */
        $this->Metadata = Metadata::getByIdp($currentPathAsArray[3]);

        try {
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
                    echo 'not yet implemented';
                    break;
                case self::$metadataPath:
                    echo $this->getEntityDescriptor();
                    break;
                case self::$ssoPath:
                    if ($this->SAMLRequest) {
                        echo $this->handleSAMLRequest();
                    }
                    break;
            }
            exit;
        } catch (\Exception $e) {
            rex_logger::logException($e);
            
            echo 'Joa - da ist ein Fehler';
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

    protected function handleSAMLRequest()
    {
        $decoded = base64_decode($this->SAMLRequest);
        $xml = gzinflate($decoded);

        $deserializationContext = new DeserializationContext();
        $deserializationContext->getDocument()->loadXML($xml);

        $authnRequest = new AuthnRequest();
        $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        if (!$this->Idp) {
            throw new Exception('Identify Provider Module not found');
        }

        if (!$this->Idp->isAuthenticated()) {
            $this->Idp->authenticate($this->SAMLRequest, $this->RelayState);
        }

        return $this->buildSAMLResponse($authnRequest);
    }

    protected function buildSAMLResponse(AuthnRequest $authnRequest) // , $request
    {
        $response = new Response();
        $response
            ->addAssertion($assertion = new Assertion())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($this->Metadata->getAssertionConsumerServiceURL())
            ->setIssuer(new Issuer($this->Metadata->getIssuer()))
            ->setStatus(new Status(new StatusCode('urn:oasis:names:tc:SAML:2.0:status:Success')))
            ->setSignature(new SignatureWriter($this->Idp->getCertificate(), $this->Idp->getPrivateKey()));

        if ($this->RelayState) {
            $response
                ->setRelayState($this->RelayState);
        }

        /** @var Subject $subject */
        $subject = $this->Idp->getSubject($this->Metadata->getNameIDFormat(), $authnRequest->getNameIDPolicy());

        $AssertionConsumerServiceURL = htmlspecialchars((string) $authnRequest->getAssertionConsumerServiceURL(), ENT_XML1, 'UTF-8');

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
                                    ->setRecipient($AssertionConsumerServiceURL)
                            )
                    )
            )
            ->setConditions(
                (new Conditions())
                    ->setNotBefore(new DateTime())
                    ->setNotOnOrAfter(new DateTime('+1 MINUTE'))
                    ->addItem(
                        new AudienceRestriction([$AssertionConsumerServiceURL])
                    )
            )
            ->addItem(
                $AttributeStatement
            )
            /*
            ->addItem(
                (new AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new AuthnContext())
                            ->setAuthnContextClassRef(SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )*/
        ;

        // dump($assertion); exit;

        return $this->sendSAMLResponse($response);
    }

    public function sendSAMLResponse($response)
    {
        $bindingFactory = new BindingFactory();
        $postBinding = $bindingFactory->create($this->Metadata->getAssertionConsumerServiceBinding());
        $messageContext = new MessageContext();
        $messageContext->setMessage($response)->asResponse();

        /** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
        $httpResponse = $postBinding->send($messageContext);

        return $httpResponse->getContent()."\n\n";
    }
}
