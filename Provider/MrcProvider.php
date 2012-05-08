<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\MrcToken;

class MrcProvider extends Provider
{
    /**
     * {@inheritDoc}
     */
    public function createTokenResponse($clientId, $secret, $code, $redirectUrl = '')
    {
        $result = $this->request('https://connect.mail.ru/oauth/token', array(
            'client_id'     => $clientId,
            'client_secret' => $secret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $redirectUrl,
        ));
        $result = json_decode($result, true);

        //        vd($result);
        if (isset($result['error'])) {
            return;
        }

//        $uid = $result['x_mailru_vid'];
        $accessToken = $result['access_token'];

        $url = 'http://www.appsmail.ru/platform/api?method=users.getInfo&app_id='.
            $clientId.'&secure=1&session_key='.$accessToken.'&sig='.
            md5('app_id='.$clientId.'method=users.getInfosecure=1session_key='.$accessToken.$secret);

        $jsonObject = json_decode($this->request($url));
        //vd($jsonObject);

        return new MrcToken($jsonObject[0], $accessToken, new \DateTime('@'.(time() + $result['expires_in'])), $result['refresh_token']);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($clientId, $scope, $redirectUrl)
    {
        return 'https://connect.mail.ru/oauth/authorize'.http_build_query(array(
            'client_id' => $clientId,
            'scope' => $scope,
            'redirect_uri' => $redirectUrl,
            'response_type' => 'code',
        ), null, '&');
    }
}
