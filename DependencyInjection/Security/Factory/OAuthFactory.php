<?php

namespace Etcpasswd\OAuthBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;

/**
 * OAuth Factory for setting up oauth related services hooking into
 * the security component
 *
 * @author Marcel Beerta <marcel@etcpasswd.de>
 */
class OAuthFactory extends AbstractFactory
{
    public function __construct()
    {
        $this->addOption('auth_provider');
        $this->addOption('client_id');
        $this->addOption('client_secret');
        $this->addOption('uid');
        $this->addOption('scope', '');
    }

    /**
     * {@inheritDoc}
     */
    protected function createAuthProvider(ContainerBuilder $container, $id,
        $config, $userProviderId)
    {
        $provider  = 'etcpasswd_oauth.authentication.provider.oauth.'.$id.'.'.$config['auth_provider'];
        $providerKey = $id.'.'.$config['auth_provider'];

        $definition = $container
            ->setDefinition($provider,
                new DefinitionDecorator('etcpasswd_oauth.authentication.provider.oauth')
            )
            ->replaceArgument(0, $providerKey);

        if ($config['provider']) {
            $definition
                ->addArgument(new Reference($userProviderId))
                ->addArgument(new Reference('security.user_checker'))
            ;
        }

        return $provider;
    }

    /**
     * {@inheritDoc}
     */
    protected function createListener($container, $id, $config, $userProvider)
    {
        $providerType   = $config['auth_provider'];
        $id = $id.'.'.$providerType;

        $oAuthProvider = sprintf('etcpasswd_oauth.provider.%s', $providerType);
        $listenerId = parent::createListener($container, $id, $config, $userProvider);

        $listener = $container->getDefinition($listenerId);
        $listener ->replaceArgument(10, new Reference($oAuthProvider));

        return $listenerId;
    }

    /**
     * {@inheritDoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);

        $node->children()
            ->scalarNode('auth_provider')->cannotBeEmpty()->isRequired()->end()
            ->scalarNode('client_id')->cannotBeEmpty()->isRequired()->end()
            ->scalarNode('client_secret')->cannotBeEmpty()->isRequired()->end()
            ->scalarNode('uid')->defaultNull()->end()
            ->scalarNode('scope')->defaultValue('')->end()
            ->scalarNode('failure_path')->cannotBeEmpty()->end();
    }

    /**
     * @{inheritDoc}
     */
    protected function getListenerId()
    {
        return 'etcpasswd_oauth.authentication.listener.oauth';
    }

    /**
     * {@inheritDoc}
     */
    public function getKey()
    {
        return null === $this->key ? 'oauth' : $this->key;
    }

    /**
     * Allows for overriding the provided key so that multiple instances of this factory can be generated
     * using different keys.
     *
     * @param string $key
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * {@inheritDoc}
     */
    public function getPosition()
    {
        return 'http';
    }
}
