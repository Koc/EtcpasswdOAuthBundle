<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\GoogleToken;

/**
 * OAuth provider for google
 *
 * @author Marcel Beerta <marcel@etcpasswd.de>
 * @link   http://code.google.com/apis/accounts/docs/OAuth2.html
 */
class GoogleProvider extends Provider
{
    /**
     * {@inheritDoc}
     */
    public function createTokenResponse($clientId, $secret, $code, $redirectUrl = '')
    {
        $response = $this->request('https://www.google.com/accounts/o8/oauth2/token', array(
            'code'          => $code,
            'client_id'     => $clientId,
            'client_secret' => $secret,
            'grant_type'    => 'authorization_code',
            'redirect_uri'  => $redirectUrl
        ));

        $data = json_decode($response);

        if (isset($data->error)) {
            return;
        }

        $me = json_decode($this->request(sprintf('https://www.googleapis.com/plus/v1/people/me?key=%s&access_token=%s', $clientId, $data->access_token)));

        return new GoogleToken($me, $data->access_token, new \DateTime('@'.(time() + $data->expires_in)));
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($clientId, $scope, $redirectUrl)
    {
        return 'https://accounts.google.com/o/oauth2/auth?'.http_build_query(array(
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUrl,
            'scope'         => $scope,
            'response_type' => 'code'
        ), null, '&');
    }
}