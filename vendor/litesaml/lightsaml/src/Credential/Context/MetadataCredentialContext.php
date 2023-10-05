<?php

namespace LightSaml\Credential\Context;

use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\RoleDescriptor;

class MetadataCredentialContext implements CredentialContextInterface
{
    /** @var KeyDescriptor */
    protected $keyDescriptor;

    /** @var RoleDescriptor */
    protected $roleDescriptor;

    /** @var EntityDescriptor */
    protected $entityDescriptor;

    public function __construct(KeyDescriptor $keyDescriptor, RoleDescriptor $roleDescriptor, EntityDescriptor $entityDescriptor)
    {
        $this->entityDescriptor = $entityDescriptor;
        $this->keyDescriptor = $keyDescriptor;
        $this->roleDescriptor = $roleDescriptor;
    }

    /**
     * @return EntityDescriptor
     */
    public function getEntityDescriptor()
    {
        return $this->entityDescriptor;
    }

    /**
     * @return KeyDescriptor
     */
    public function getKeyDescriptor()
    {
        return $this->keyDescriptor;
    }

    /**
     * @return RoleDescriptor
     */
    public function getRoleDescriptor()
    {
        return $this->roleDescriptor;
    }
}
