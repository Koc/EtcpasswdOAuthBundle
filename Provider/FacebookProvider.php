<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\FacebookToken;

/**
 * OAuth provider for facebook
 *
 * @author Marcel Beerta <marcel@etcpasswd.de>
 * @link   http://developers.facebook.com/docs/authentication/
 */
class FacebookProvider extends Provider
{
    /**
     * {@inheritDoc}
     */
    public function createTokenResponse($clientId, $secret, $code, $redirectUrl = '')
    {
        $url = 'https://graph.facebook.com/oauth/access_token?'.http_build_query(array(
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUrl,
            'client_secret' => $secret,
            'code'          => $code
        ), null, '&');

        $result = array();
        parse_str($this->request($url), $result);

        if (isset($result['error'])) {
            return;
        }

        $json = json_decode($this->request(sprintf('https://graph.facebook.com/me?access_token=%s', $result['access_token'])));

        return new FacebookToken($json, $result['access_token'], new \DateTime('@'.(time() + $result['expires'])));
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($clientId, $scope, $redirectUrl)
    {
        return 'https://www.facebook.com/dialog/oauth?'.http_build_query(array(
            'client_id'    => $clientId,
            'redirect_uri' => $redirectUrl,
            'scope'        => $scope,
        ), null, '&');
    }
}
