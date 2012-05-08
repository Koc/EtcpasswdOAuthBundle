<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\VkToken;

class VkProvider extends Provider
{
    /**
     * {@inheritDoc}
     */
    public function createTokenResponse($clientId, $secret, $code, $redirectUrl = '')
    {
        $url = 'https://oauth.vk.com/access_token?'.http_build_query(array(
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUrl,
            'client_secret' => $secret,
            'code'          => $code,
        ), null, '&');

        $result = json_decode($this->request($url), true);

        if (isset($result['error'])) {
            return;
        }

        $accessToken = $result['access_token'];

        // call user api to fetch some details
        $url = 'https://api.vk.com/method/getProfiles?uids='.$result['user_id'].'&access_token='
            .$accessToken.'&fields=uid,first_name,screen_name,last_name,nickname,domain,sex,bdate,photo_big';

        $jsonObject = json_decode($this->request($url));

        return new VkToken($jsonObject->response[0], $accessToken, new \DateTime('@'.(time() + $result['expires_in'])));
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($clientId, $scope, $redirectUrl)
    {
        return 'http://oauth.vk.com/authorize?'.http_build_query(array(
            'client_id'     => $clientId,
            'scope'         => $scope,
            'redirect_uri'  => $redirectUrl,
            'response_type' => 'code',
        ), null, '&');
    }
}
