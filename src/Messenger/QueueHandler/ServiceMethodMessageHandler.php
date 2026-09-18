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

namespace Wlindabla\ShareServiceBundle\Messenger\QueueHandler;

use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Wlindabla\ShareServiceBundle\Messenger\Message\ServiceMethodMessage;

/**
 * Executes, asynchronously, the service method calls sent as
 * {@see ServiceMethodMessage} instances. Acts as a Symfony Messenger
 * handler: it receives the message, resolves the target service from a
 * restricted locator, then invokes the requested method with the supplied
 * parameters.
 *
 * SECURITY / DESIGN NOTE (fixes a bug present in earlier versions of this
 * class): this handler used to implement {@see \Symfony\Contracts\Service\ServiceSubscriberInterface}
 * and declare `getSubscribedServices()` as `static`, while reading an
 * instance property (`$this->_servicesClass`) inside that static method —
 * this does not compile/run, since a static method has no `$this`.
 *
 * The fix replaces that pattern with a plain, injected PSR-11
 * {@see ContainerInterface}, built by the bundle's DI extension as a
 * Symfony `ServiceLocator` containing *only* the FQCNs explicitly
 * configured under `wlindabla_share_service.async_method_dispatcher.allowed_services`.
 * This keeps the original intent (only allow-listed services can be
 * resolved and invoked from a message payload, never an arbitrary
 * attacker-controlled class name) while being valid, working PHP.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package <https://github.com/Agbokoudjo/>
 */
#[AsMessageHandler(fromTransport: 'async_app_transport', handles: ServiceMethodMessage::class)]
final class ServiceMethodMessageHandler implements ServiceMethodMessageHandlerInterface
{
    /**
     * @param ContainerInterface $allowedServices A locator restricted to the FQCNs configured in
     *                                             `wlindabla_share_service.async_method_dispatcher.allowed_services`.
     */
    public function __construct(private readonly ContainerInterface $allowedServices)
    {
    }

    public function __invoke(ServiceMethodMessage $message): void
    {
        $serviceName = $message->getServiceName();

        if (!$this->allowedServices->has($serviceName)) {
            throw new \RuntimeException(sprintf(
                'Service "%s" is not allow-listed for asynchronous method dispatch. Add it to the'
                . ' "wlindabla_share_service.async_method_dispatcher.allowed_services" configuration key.',
                $serviceName,
            ));
        }

        try {
            $service = $this->allowedServices->get($serviceName);
        } catch (NotFoundExceptionInterface $e) {
            throw new \RuntimeException(sprintf('Unable to resolve service "%s".', $serviceName), 0, $e);
        }

        $method = $message->getMethod();

        if (!method_exists($service, $method)) {
            throw new \RuntimeException(sprintf('Service "%s" has no method "%s".', $serviceName, $method));
        }

        $service->$method(...$message->getParams());
    }
}
