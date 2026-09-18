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

use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DelayStamp;
use Wlindabla\ShareServiceBundle\Messenger\Message\ServiceMethodMessage;

/**
 * Default {@see AsyncMethodDispatcherInterface} implementation: wraps the
 * requested service call in a {@see ServiceMethodMessage} and dispatches it
 * on the Symfony Messenger bus, optionally delayed until a given date.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package <https://github.com/Agbokoudjo/>
 */
final class AsyncMethodDispatcher implements AsyncMethodDispatcherInterface
{
    public function __construct(private readonly MessageBusInterface $bus)
    {
    }

    public function dispatch(string $service, string $method, array $params = [], ?\DateTimeInterface $date = null): void
    {
        $stamps = [];

        if ($date !== null) {
            $delay = 1000 * ($date->getTimestamp() - time());
            if ($delay > 0) {
                $stamps[] = new DelayStamp($delay);
            }
        }

        $this->bus->dispatch(new ServiceMethodMessage($service, $method, $params), $stamps);
    }
}
