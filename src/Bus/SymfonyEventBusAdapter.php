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

namespace Wlindabla\ShareServiceBundle\Bus;

use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Symfony adapter for {@see EventBusInterface}.
 *
 * Implements the abstraction by delegating to Symfony's EventDispatcher.
 * This class is the bridge between the framework-agnostic business
 * abstraction and Symfony itself.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class SymfonyEventBusAdapter implements EventBusInterface
{
    public function __construct(
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public function dispatch(object $event, ?string $eventName = null): object
    {
        return $this->eventDispatcher->dispatch($event, $eventName);
    }
}
