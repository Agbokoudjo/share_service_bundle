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

namespace Wlindabla\ShareServiceBundle\Messenger\Message;

/**
 * Message dispatched on the message bus to asynchronously execute a
 * specific method of a given service.
 *
 * Carries everything needed to perform the call:
 *  - the name (FQCN) of the service to invoke,
 *  - the method of that service to call,
 *  - the parameters to pass to that method.
 *
 * Typically used with Symfony Messenger to defer or delegate execution to
 * a worker or a processing queue.
 *
 * Example:
 * ```php
 * $message = new ServiceMethodMessage(UserNotifier::class, 'sendWelcomeEmail', ['userId' => 42]);
 * $bus->dispatch($message);
 * ```
 *
 * The associated handler receives this message and dynamically invokes the
 * corresponding method. See {@see \Wlindabla\ShareServiceBundle\Messenger\QueueHandler\ServiceMethodMessageHandler}
 * for the (restricted, allow-listed) resolution of `$serviceName`.
 *
 * Requires PHP 8.2+ (`readonly class` modifier).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final readonly class ServiceMethodMessage
{
    /**
     * @param string               $serviceName Fully qualified class name (FQCN) of the service to invoke.
     * @param string               $method      Name of the method to call on that service.
     * @param array<string, mixed> $params      Parameters passed to the invoked method.
     */
    public function __construct(
        private string $serviceName,
        private string $method,
        private array $params = [],
    ) {
    }

    /** Fully qualified class name (FQCN) of the service to invoke. */
    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    /** Name of the method to call on the resolved service. */
    public function getMethod(): string
    {
        return $this->method;
    }

    /** Parameters passed to the invoked method. */
    public function getParams(): array
    {
        return $this->params;
    }
}
