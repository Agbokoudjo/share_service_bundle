<?php

declare(strict_types=1);

/*
 * This file is part of the project by AGBOKOUDJO Franck.
 *
 * (c) AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * Phone: +229 01 67 25 18 86
 * LinkedIn: https://www.linkedin.com/in/internationales-web-apps-services-120520193/
 * Github: https://github.com/Agbokoudjo/
 * Company: INTERNATIONALES WEB APPS & SERVICES
 *
 * For more information, please feel free to contact the author.
 */

namespace Wlindabla\ShareServiceBundle;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Wlindabla\ShareServiceBundle\ArgumentResolver\IdEncryptionRequestArgumentValueResolver;
use Wlindabla\ShareServiceBundle\Messenger\QueueHandler\ServiceMethodMessageHandler;
use Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionService;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service_locator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Entry point of the wlindabla/share-service-bundle library.
 *
 * Uses {@see AbstractBundle} (available since Symfony 6.1) so that
 * configuration tree, container extension and Symfony config all live in a
 * single class. This is the recommended approach for a small,
 * self-contained bundle and keeps this package compatible with Symfony
 * 6.4, 7.x and 8.x without a separate DependencyInjection\Extension class.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class WlindablaShareServiceBundle extends AbstractBundle
{
    protected string $extensionAlias = 'wlindabla_share_service';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->arrayNode('id_encryption')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('encryption_key')
                            ->defaultNull()
                            ->info('Base64-encoded 256-bit key. Generate one with IdEncryptionService::generateEncryptionKey(). Required only if the id_encryption service is used.')
                        ->end()
                        ->arrayNode('identity_key_collection')
                            ->scalarPrototype()->end()
                            ->defaultValue(['id', 'code', 'slug'])
                            ->info('Route attribute names checked, in order, by IdEncryptionRequestArgumentValueResolver.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('token_hasher')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('algorithm')->defaultNull()->info('A PASSWORD_* constant value, or null to auto-select Argon2id with bcrypt fallback.')->end()
                        ->arrayNode('options')
                            ->useAttributeAsKey('name')
                            ->variablePrototype()->end()
                            ->defaultValue([])
                            ->info('Options passed to password_hash(); defaults are algorithm-specific secure values.')
                        ->end()
                    ->end()
                ->end()
                ->floatNode('identity_similarity_threshold')
                    ->defaultValue(88.0)
                    ->info('Percentage (0-100) above which two identities are considered a likely duplicate.')
                ->end()
                ->arrayNode('trusted_ips')
                    ->scalarPrototype()->end()
                    ->defaultValue(['127.0.0.1', '::1'])
                    ->info('IPs exempt from BrowserRequestValidator checks (monitoring, CI/CD, internal VPS).')
                ->end()
                ->arrayNode('async_method_dispatcher')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('transport')->defaultValue('async_app_transport')->end()
                        ->arrayNode('allowed_services')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                            ->info('FQCNs of services that ServiceMethodMessageHandler is allowed to resolve and invoke. Nothing outside this list can be called — see ServiceMethodMessageHandler docblock.')
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * NOTE ON THE SIGNATURE: with AbstractBundle, $container is a
     * ContainerConfigurator (the fluent services()/parameters()/import()
     * API used in Symfony's PHP config files) and $builder is the
     * underlying, lower-level ContainerBuilder (used here for
     * removeDefinition(), which ContainerConfigurator does not expose).
     * An earlier draft of this method mixed the two up — fixed here.
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import(__DIR__ . '/../config/services.php');

        $builder->setParameter('wlindabla_share_service.id_encryption.encryption_key', $config['id_encryption']['encryption_key']);
        $builder->setParameter('wlindabla_share_service.id_encryption.identity_key_collection', $config['id_encryption']['identity_key_collection']);
        $builder->setParameter('wlindabla_share_service.token_hasher.algorithm', $config['token_hasher']['algorithm']);
        $builder->setParameter('wlindabla_share_service.token_hasher.options', $config['token_hasher']['options']);
        $builder->setParameter('wlindabla_share_service.identity_similarity_threshold', $config['identity_similarity_threshold']);
        $builder->setParameter('wlindabla_share_service.trusted_ips', $config['trusted_ips']);
        $builder->setParameter('wlindabla_share_service.async_method_dispatcher.transport', $config['async_method_dispatcher']['transport']);

        // Only register the ID-encryption service and its argument resolver
        // once a key has been configured, so the bundle does not throw at
        // boot time for applications that never enable this feature.
        if ($config['id_encryption']['encryption_key'] === null) {
            $builder->removeDefinition(IdEncryptionService::class);
            $builder->removeDefinition(IdEncryptionRequestArgumentValueResolver::class);
        }

        // --- The ServiceLocator wiring for the async method dispatcher ---
        //
        // ServiceMethodMessageHandler must NEVER be able to resolve an
        // arbitrary class name coming from a queued message payload — only
        // the FQCNs an app developer explicitly whitelisted in
        // `async_method_dispatcher.allowed_services`. A Symfony
        // ServiceLocator is exactly that: a tiny, separate PSR-11
        // container that only knows the service ids you give it at
        // compile time (here), nothing else — even though the full app
        // container has hundreds of other services available.
        //
        // service($id) builds a lazy reference to an existing service
        // definition (it does not instantiate anything yet).
        // service_locator($map) turns an [id => reference] map into a
        // ServiceLocatorArgument; Symfony's compiler then generates a
        // real, private `ServiceLocator` service from it and injects that
        // as the `$allowedServices` constructor argument below.
        $locatorMap = [];
        foreach ($config['async_method_dispatcher']['allowed_services'] as $serviceId) {
            $locatorMap[$serviceId] = service($serviceId);
        }

        $container->services()
            ->get(ServiceMethodMessageHandler::class)
            ->arg('$allowedServices', service_locator($locatorMap));
    }
}
