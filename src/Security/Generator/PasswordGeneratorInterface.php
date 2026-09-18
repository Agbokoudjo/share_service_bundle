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

namespace Wlindabla\ShareServiceBundle\Security\Generator;

/**
 * Contract for generating random, secure passwords.
 */
interface PasswordGeneratorInterface
{
    /**
     * Generates a random password satisfying the complexity requirements.
     *
     * @param int $length The minimum required length (16).
     */
    public function generate(int $length, bool $includeSymbols = true, bool $excludeAmbiguous = false): string;
}
