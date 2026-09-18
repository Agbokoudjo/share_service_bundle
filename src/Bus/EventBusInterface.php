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

/**
 * Abstraction over the domain event bus.
 *
 * Allows dispatching domain events without depending on a specific
 * framework (Symfony, Laravel, etc.). The concrete implementation lives in
 * the infrastructure layer of the consuming application.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
interface EventBusInterface
{
    /**
     * Dispatches an event on the bus.
     *
     * @param object      $event     The event to dispatch.
     * @param string|null $eventName Optional explicit event name.
     */
    public function dispatch(object $event, ?string $eventName = null): object;
}
