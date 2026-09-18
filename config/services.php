<?php

declare(strict_types=1);

/*
 * This file is part of the project by AGBOKOUDJO Franck.
 *
 * (c) AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * Company: INTERNATIONALES WEB APPS & SERVICES
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Wlindabla\ShareServiceBundle\ArgumentResolver\IdEncryptionRequestArgumentValueResolver;
use Wlindabla\ShareServiceBundle\Bus\EventBusInterface;
use Wlindabla\ShareServiceBundle\Bus\SymfonyEventBusAdapter;
use Wlindabla\ShareServiceBundle\Form\ProcessingErrorFormHandler;
use Wlindabla\ShareServiceBundle\Messenger\QueueHandler\AsyncMethodDispatcher;
use Wlindabla\ShareServiceBundle\Messenger\QueueHandler\AsyncMethodDispatcherInterface;
use Wlindabla\ShareServiceBundle\Messenger\QueueHandler\ServiceMethodMessageHandler;
use Wlindabla\ShareServiceBundle\Security\Browser\BrowserChallengeSigner;
use Wlindabla\ShareServiceBundle\Security\Browser\BrowserRequestValidator;
use Wlindabla\ShareServiceBundle\Security\Browser\UserAgentParser;
use Wlindabla\ShareServiceBundle\Security\Browser\UserAgentParserInterface;
use Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionInterface;
use Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionService;
use Wlindabla\ShareServiceBundle\Security\Generator\GenerateTemporaryPasswordService;
use Wlindabla\ShareServiceBundle\Security\Generator\MfaCodeGenerator;
use Wlindabla\ShareServiceBundle\Security\Generator\MfaCodeGeneratorInterface;
use Wlindabla\ShareServiceBundle\Security\Generator\PasswordGeneratorInterface;
use Wlindabla\ShareServiceBundle\Security\Generator\RandomPasswordGenerator;
use Wlindabla\ShareServiceBundle\Security\Generator\RandomTokenGenerator;
use Wlindabla\ShareServiceBundle\Security\Generator\TokenGeneratorInterface;
use Wlindabla\ShareServiceBundle\Security\Hash\NativeTokenHasher;
use Wlindabla\ShareServiceBundle\Security\Hash\TokenHasherInterface;
use Wlindabla\ShareServiceBundle\Serializer\SerializerFacade;
use Wlindabla\ShareServiceBundle\Similarity\IdentitySimilarityChecker;

return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure();

    // --- Bus -----------------------------------------------------------
    $services->set(EventBusInterface::class, SymfonyEventBusAdapter::class);

    // --- Form ------------------------------------------------------------
    $services->set(ProcessingErrorFormHandler::class);

    // --- Messenger / async method dispatch --------------------------------
    $services->set(AsyncMethodDispatcherInterface::class, AsyncMethodDispatcher::class);
    // $allowedServices is wired by WlindablaShareServiceBundle::loadExtension()
    // from the `async_method_dispatcher.allowed_services` configuration key.
    $services->set(ServiceMethodMessageHandler::class)
        ->arg('$allowedServices', []);

    // --- Security / Browser -------------------------------------------
    $services->set(UserAgentParserInterface::class, UserAgentParser::class);
    $services->set(BrowserRequestValidator::class)
        ->arg('$trustedIps', '%wlindabla_share_service.trusted_ips%');
    $services->set(BrowserChallengeSigner::class)
        ->arg('$appSecret', '%kernel.secret%');

    // --- Security / Encryption ------------------------------------------
    $services->set(IdEncryptionInterface::class, IdEncryptionService::class)
        ->arg('$encryptionKey', '%wlindabla_share_service.id_encryption.encryption_key%');
    $services->set(IdEncryptionRequestArgumentValueResolver::class)
        ->arg('$identityKeyCollection', '%wlindabla_share_service.id_encryption.identity_key_collection%')
        ->tag('controller.argument_value_resolver', ['priority' => 100]);

    // --- Security / Generator -------------------------------------------
    $services->set(PasswordGeneratorInterface::class, RandomPasswordGenerator::class);
    $services->set(GenerateTemporaryPasswordService::class);
    $services->set(MfaCodeGeneratorInterface::class, MfaCodeGenerator::class);
    $services->set(TokenGeneratorInterface::class, RandomTokenGenerator::class);

    // --- Security / Hash --------------------------------------------------
    $services->set(TokenHasherInterface::class, NativeTokenHasher::class)
        ->arg('$algorithm', '%wlindabla_share_service.token_hasher.algorithm%')
        ->arg('$options', '%wlindabla_share_service.token_hasher.options%');

    // --- Serializer -------------------------------------------------------
    $services->set(SerializerFacade::class);

    // --- Similarity ------------------------------------------------------
    $services->set(IdentitySimilarityChecker::class)
        ->arg('$similarityThreshold', '%wlindabla_share_service.identity_similarity_threshold%');
};
