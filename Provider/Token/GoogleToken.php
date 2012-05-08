<?php

namespace Etcpasswd\OAuthBundle\Provider\Token;

/**
 *
 * @author Marcel Beerta <marcel@etcpasswd.de>
 */
class GoogleToken implements TokenResponseInterface
{
    private $json;
    private $accessToken;
    private $expiresAt;

    /**
     * Constructs a new token
     *
     * @param object $jsonObject Json object
     * @param string $accessToken Api access token
     * @param \DateTime $expiresAt Expires at date
     */
    public function __construct($jsonObject, $accessToken, \DateTime $expiresAt)
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
    public function getUsername($field = 'id')
    {
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
        return 'google';
    }

    public function getJson()
    {
        return $this->json;
    }
}
