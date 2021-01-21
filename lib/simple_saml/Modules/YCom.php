<?php

namespace REDAXO\Simple_SAML\Modules;

use GuzzleHttp\Psr7\ServerRequest;
use LightSaml\ClaimTypes;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\Subject;
use LightSaml\SamlConstants;
use REDAXO\Simple_SAML\Simple_SAML;

class YCom extends AbstractModule
{
    public static $key = 'YCom';

    public function getCertificate()
    {
        $cert = new X509Certificate();
        $cert->loadPem($this->data['x509cert']);
        return $cert;
    }

    public function getPrivateKey()
    {
        $securityKey = KeyHelper::createPrivateKey($this->data['privateKey'], '');
        return $securityKey;
    }

    public function getIdentifier()
    {
        return $this->data['entityId'];
    }

    public function getSubject($format, $nameIDPolicy)
    {
        // Todo: createAllowed
        switch ($format) {
            case SamlConstants::NAME_ID_FORMAT_UNSPECIFIED: // Sp knows the format - individual
            case SamlConstants::NAME_ID_FORMAT_EMAIL: // email
                $value = \rex_ycom_user::getMe()->getValue('email');
                break;
            case SamlConstants::NAME_ID_FORMAT_PERSISTENT: // persistent id. here: could be login OR email
                $value = \rex_ycom_user::getMe()->getValue('email');
                break;
            case SamlConstants::NAME_ID_FORMAT_TRANSIENT: // no info about identity
                $value = \rex_ycom_user::getMe()->getValue('email');
                break;
            default:
                $format = SamlConstants::NAME_ID_FORMAT_UNSPECIFIED;
                $value = \rex_ycom_user::getMe()->getValue('email');
        }

        return (new Subject())
            ->setNameID(new NameID(
                $value,
                $format
            ));
    }

    public function logoutUser(Simple_SAML $simple_SAML)
    {
        return true;
    }

    public function getClaimValue($claim)
    {
        /** @var \rex_yform_manager_dataset $user */
        $user = \rex_ycom_user::getMe();
        if (!$user) {
            return false;
        }

        switch ($claim) {
            case ClaimTypes::COMMON_NAME:
            case ClaimTypes::NAME:
                $name = [$user->getValue('firstname'), $user->getValue('name')];
                return implode(' ', $name);
                break;
            case ClaimTypes::ADFS_1_EMAIL:
            case ClaimTypes::EMAIL_ADDRESS:
                return $user->getValue('email');
                break;
            case ClaimTypes::GIVEN_NAME:
                return $user->getValue('firstname');
                break;
            case ClaimTypes::SURNAME:
                return $user->getValue('name');
                break;
            case ClaimTypes::ADFS_1_UPN:
            case ClaimTypes::UPN:
                return $user->getValue('login');
                break;
            case ClaimTypes::ROLE:
            case ClaimTypes::GROUP:
                $groups = [];
                foreach ($user->getRelatedCollection('ycom_groups') as $group) {
                    $groups[] = $group->getId();
                }
                return $groups;
                break;
            case ClaimTypes::NAME_ID:
            case ClaimTypes::PPID:
                return $user->getValue('id');
                break;
            case ClaimTypes::AUTHENTICATION_TIMESTAMP:
                return (new \DateTime())->format(DATE_ATOM);
        }
        return false;
    }

    public function authenticate($SAMLRequest, $RelayState)
    {
        $url = $this->getSSOUrl();
        $urlParams = [];
        $urlParams['SAMLRequest'] = $SAMLRequest;
        if ($RelayState) {
            $urlParams['RelayState'] = $RelayState;
        }

        $returnToUrl = $url.'?'.http_build_query($urlParams, '', '&');

        $login_id = \rex_config::get('ycom/auth', 'article_id_login');
        if (!$login_id) {
            throw new \Exception('YCom - LoginId is not defined');
        }

        $loginUrl = rex_getUrl($login_id, '', [
            'returnTo' => $returnToUrl,
        ], '&');

        $loginUrl = ServerRequest::fromGlobals()->getUri()->getScheme().'://'.ServerRequest::fromGlobals()->getUri()->getHost().$loginUrl;

        \rex_response::sendRedirect($loginUrl);
    }

    public function isAuthenticated()
    {
        return (\rex_ycom_user::getMe()) ? true : false;
    }
}
