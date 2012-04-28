<?php

namespace Etcpasswd\OAuthBundle\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface,
    Symfony\Component\Security\Core\Exception\AuthenticationException,
    Symfony\Component\Security\Core\Authentication\Token\TokenInterface,
    Symfony\Component\Security\Core\User\UserCheckerInterface,
    Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface,
    Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;

use Etcpasswd\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

/**
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
class OAuthProvider implements AuthenticationProviderInterface
{
    protected $providerKey;
    protected $userProvider;
    protected $userChecker;

    public function __construct($providerKey, UserProviderInterface $userProvider = null, UserCheckerInterface $userChecker = null)
    {
        if (null !== $userProvider && null === $userChecker) {
            throw new \InvalidArgumentException('$userChecker cannot be null, if $userProvider is not null.');
        }

        $this->providerKey = $providerKey;
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return;
        }

        if (null === $this->userProvider) {
            $authenticatedToken = new OAuthToken($this->providerKey, $token->getResponse());
            $authenticatedToken->setAuthenticated(true);
            $authenticatedToken->setUser($token->getResponse()->getUsername());

            return $authenticatedToken;
        }

        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        if ($user) {
            $this->userChecker->checkPostAuth($user);

            $authenticatedToken = new OAuthToken($this->providerKey, $token->getResponse(), $user->getRoles());
            $authenticatedToken->setAuthenticated(true);
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('OAuth Authentication Failed.');
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken && $this->providerKey === $token->getProviderKey();
    }
}