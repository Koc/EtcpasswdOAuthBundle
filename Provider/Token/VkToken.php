<?php

namespace Etcpasswd\OAuthBundle\Provider\Token;

class VkToken implements TokenResponseInterface
{
    private $json;
    private $accessToken;
    private $expiresAt;

    /**
     * Constructs a new token
     *
     * @param object $jsonObject  Json object
     * @param string $accessToken Api access token
     * @param string $expiresAt   expires at date
     */
    public function __construct($jsonObject, $accessToken, $expiresAt)
    {
        $this->json = $jsonObject;
        $this->accessToken = $accessToken;
        $this->expiresAt = $expiresAt;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername($field = 'uid')
    {
        if ('uid' === $field) {
            return (string)$this->json->$field;
        }

        return $this->json->$field;
    }

    /**
     * {@inheritDoc}
     */
    public function isLongLived()
    {
        return false;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function getProviderKey()
    {
        return 'vk';
    }

    public function getJson()
    {
        return $this->json;
    }
}
