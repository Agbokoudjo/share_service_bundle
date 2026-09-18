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

/**
 * Defines the contract for asynchronously dispatching a method call on a
 * service. Delegates execution to a message queue via a message bus, so
 * the call can be processed later or after an explicit delay.
 *
 * Typical uses:
 *  - Run a business method after a given delay.
 *  - Offload a heavy task to an asynchronous worker to avoid blocking the HTTP request.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package <https://github.com/Agbokoudjo/>
 */
interface AsyncMethodDispatcherInterface
{
    /**
     * @param string                    $service Fully qualified class name (FQCN) of the service to invoke.
     * @param string                    $method  Name of the method to call on that service.
     * @param array<string, mixed>      $params  Parameters passed to the invoked method.
     * @param \DateTimeInterface|null   $date    Deferred execution date (null = immediate execution).
     */
    public function dispatch(string $service, string $method, array $params = [], ?\DateTimeInterface $date = null): void;
}
