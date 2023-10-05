<?php

namespace LightSaml\Context\Profile;

use LightSaml\Meta\TrustOptions\TrustOptions;
use LightSaml\Model\Metadata\EntityDescriptor;

class EntityContext extends AbstractProfileContext
{
    /** @var string */
    private $entityId;

    /** @var EntityDescriptor */
    private $entityDescriptor;

    /** @var TrustOptions */
    private $trustOptions;

    /**
     * @return string
     */
    public function getEntityId()
    {
        return $this->entityId;
    }

    /**
     * @param string $entityId
     *
     * @return EntityContext
     */
    public function setEntityId($entityId)
    {
        $this->entityId = $entityId;

        return $this;
    }

    /**
     * @return EntityDescriptor
     */
    public function getEntityDescriptor()
    {
        return $this->entityDescriptor;
    }

    /**
     * @return EntityContext
     */
    public function setEntityDescriptor(EntityDescriptor $entityDescriptor)
    {
        $this->entityDescriptor = $entityDescriptor;

        return $this;
    }

    /**
     * @return TrustOptions
     */
    public function getTrustOptions()
    {
        return $this->trustOptions;
    }

    /**
     * @return EntityContext
     */
    public function setTrustOptions(TrustOptions $trustOptions)
    {
        $this->trustOptions = $trustOptions;

        return $this;
    }
}
