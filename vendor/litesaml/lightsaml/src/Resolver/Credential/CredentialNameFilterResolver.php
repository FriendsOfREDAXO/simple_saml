<?php

namespace LightSaml\Resolver\Credential;

use LightSaml\Credential\CredentialInterface;
use LightSaml\Credential\Criteria\CredentialNameCriteria;
use LightSaml\Criteria\CriteriaSet;

class CredentialNameFilterResolver extends AbstractQueryableResolver
{
    /**
     * @param CredentialInterface[] $arrCredentials
     *
     * @return CredentialInterface[]
     */
    public function resolve(CriteriaSet $criteriaSet, array $arrCredentials = [])
    {
        if (false == $criteriaSet->has(CredentialNameCriteria::class)) {
            return $arrCredentials;
        }

        $result = [];
        foreach ($criteriaSet->get(CredentialNameCriteria::class) as $criteria) {
            /* @var CredentialNameCriteria $criteria */
            foreach ($arrCredentials as $credential) {
                $arrCredentialNames = $credential->getKeyNames();
                $criteriaName = $criteria->getName();
                foreach ($arrCredentialNames as $credentialName) {
                    if ($credentialName == $criteriaName) {
                        $result[] = $credential;
                        break;
                    }
                }
            }
        }

        return $result;
    }
}
