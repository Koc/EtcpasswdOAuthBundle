<?php

namespace Etcpasswd\OAuthBundle\Provider\Token;

class OdnoklassnikiToken implements TokenResponseInterface
{
    private $json;
    private $accessToken;
    private $expiresAt;
    private $refreshToken;

    /**
     * Constructs a new token
     *
     * @param object $jsonObject Json object
     * @param string $accessToken Api access token
     * @param \DateTime $expiresAt Expires at date
     * @param string $refreshToken Refresh token
     */
    public function __construct($jsonObject, $accessToken, \DateTime $expiresAt, $refreshToken)
    {
        $this->json = $jsonObject;
        $this->accessToken = $accessToken;
        $this->expiresAt = $expiresAt;
        $this->refreshToken = $refreshToken;
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
        return 'odnoklassniki';
    }

    public function getJson()
    {
        return $this->json;
    }

    public function getRefreshToken()
    {
        return $this->refreshToken;
    }
}
