<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\OdnoklassnikiToken;

class OdnoklassnikiProvider extends Provider
{
    protected $applicationKey;

    public function setApplicationKey($applicationKey)
    {
        $this->applicationKey = $applicationKey;
    }

    /**
     * {@inheritDoc}
     */
    public function createTokenResponse($clientId, $secret, $code, $redirectUrl = '')
    {
        $result = $this->request('http://api.odnoklassniki.ru/oauth/token.do', array(
            'client_id'     => $clientId,
            'client_secret' => $secret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $redirectUrl,
        ));
        $result = json_decode($result, true);

        if (isset($result['error'])) {
            return;
        }

        $accessToken = $result['access_token'];

        $url = 'http://api.odnoklassniki.ru/api/users/getLoggedInUser?application_key='.$this->applicationKey.'&client_id='.
            $clientId.'&access_token='.$accessToken.'&format=json&sig='.
            md5('application_key='.$this->applicationKey.'client_id='.$clientId.'format=json'.md5($accessToken.$secret));

        $uid = json_decode($this->request($url));

        $url = 'http://api.odnoklassniki.ru/api/users/getInfo?application_key='.$this->applicationKey.'&client_id='.
            $clientId.'&access_token='.$accessToken.'&format=json&uids='.$uid.'&fields=uid,first_name,last_name,name,gender,birthday,url_profile&sig='.
            md5('application_key='.$this->applicationKey.'client_id='.$clientId.'fields=uid,first_name,last_name,name,gender,birthday,url_profileformat=jsonuids='.
            $uid.md5($accessToken.$secret));

        $jsonObject = json_decode($this->request($url));

        return new OdnoklassnikiToken($jsonObject[0], $accessToken, new \DateTime('@'.(time() + 30 * 60)), $result['refresh_token']);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($clientId, $scope, $redirectUrl)
    {
        return 'http://www.odnoklassniki.ru/oauth/authorize?'.http_build_query(array(
            'client_id'     => $clientId,
            'scope'         => $scope,
            'redirect_uri'  => $redirectUrl,
            'response_type' => 'code',
        ), null, '&');
    }
}
