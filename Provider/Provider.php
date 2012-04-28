<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Buzz\Client\ClientInterface;
use Buzz\Message\Request;
use Buzz\Message\Response;

/**
 * Base Provider class
 *
 * @author Marcel Beerta <marcel@etcpasswd.de>
 */
abstract class Provider implements ProviderInterface
{
    protected $client;

    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
        if (method_exists($this->client, 'setVerifyPeer')) {
            $this->client->setVerifyPeer(false);
        }
    }

    protected function request($url, array $postData = array(), $method = null)
    {
        if (null === $method) {
            $method = $postData ? Request::METHOD_POST : Request::METHOD_GET;
        }

        $request = new Request($method, $url);
        if ($postData) {
            $request->setContent(http_build_query($postData, null, '&'));
        }
        $response = new Response();
        $this->client->send($request, $response);

        return $response->getContent();
    }
}
