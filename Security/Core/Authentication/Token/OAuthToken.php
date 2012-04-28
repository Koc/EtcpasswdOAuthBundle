<?php

namespace Etcpasswd\OAuthBundle\Security\Core\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

use Etcpasswd\OAuthBundle\Provider\Token\TokenResponseInterface;
/**
 *
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
class OAuthToken extends AbstractToken
{
    private $response;

    private $providerKey;

    public function __construct($providerKey, TokenResponseInterface $response, array $roles = array())
    {
        parent::__construct($roles);
        $this->providerKey = $providerKey;
        $this->response = $response;
        $this->setAttribute('access_token', $response->getAccessToken());
        $this->setAttribute('via', $response->getProviderKey());
        $this->setAttribute('data', $response->getJson());
    }

    public function getCredentials()
    {
        return $this->response->getAccessToken();
    }

    public function eraseCredentials()
    {
        unset($this->response);
        parent::eraseCredentials();
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }
}
