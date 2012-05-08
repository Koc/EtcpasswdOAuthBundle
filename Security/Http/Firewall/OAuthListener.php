<?php

namespace Etcpasswd\OAuthBundle\Security\Http\Firewall;

use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use Etcpasswd\OAuthBundle\Provider\ProviderInterface;
use Etcpasswd\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

class OAuthListener extends AbstractAuthenticationListener
{
    private $oauthProvider;
    protected $httpUtils;

    /**
     * {@inheritdoc}
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager,
            SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey,
            array $options = array(), AuthenticationSuccessHandlerInterface $successHandler = null,
            AuthenticationFailureHandlerInterface $failureHandler = null, LoggerInterface $logger = null,
            EventDispatcherInterface $dispatcher = null, ProviderInterface $oauthProvider)
    {
        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils,
                $providerKey, $options, $successHandler, $failureHandler, $logger, $dispatcher);
        $this->oauthProvider = $oauthProvider;
        $this->httpUtils = $httpUtils;
    }

    /**
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        $code = $request->get('code');

        // redirect to auth provider
        if (!$code) {
            return $this->createProviderRedirectResponse($request);
        }

        $token = $this->oauthProvider->createTokenResponse(
            $this->options['client_id'],
            $this->options['client_secret'],
            $code,
            $this->assembleRedirectUrl($this->options['check_path'], $request)
        );

        if (null === $token) {
            throw new AuthenticationException('Authentication failed');
        }

        if (null === $this->options['uid']) {
            $username = $token->getUsername();
        } else {
            $username = $token->getUsername($this->options['uid']);
        }

        $authToken = new OAuthToken($this->providerKey, $token);
        $authToken->setUser($username);

        return $this->authenticationManager->authenticate($authToken);
    }

    private function createProviderRedirectResponse(Request $request)
    {
        $url = $this->oauthProvider->getAuthorizationUrl(
            $this->options['client_id'],
            $this->options['scope'],
            $this->assembleRedirectUrl($this->options['check_path'], $request)
        );

        return $this->httpUtils->createRedirectResponse($request, $url);
    }

    private function assembleRedirectUrl($path, Request $request)
    {
        $url = $request->getUriForPath($path);

        if ($targetUrl = $request->get($this->options['target_path_parameter'], null, true)) {
            $url .= '?'.$this->options['target_path_parameter'].'='.urlencode($targetUrl);
        }

        return $url;
    }
}
