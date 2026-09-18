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
 * Generates the MFA code sent by email: 13 digits + 7 uppercase letters,
 * randomly shuffled (20 characters total).
 *
 * Requires PHP 8.3+ (typed interface constants below).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
interface MfaCodeGeneratorInterface
{
    public const int DIGIT_COUNT = 13;
    public const int LETTER_COUNT = 7;

    /**
     * @return string The plaintext code (to be emailed, never stored as-is).
     *                 20 characters: 13 digits + 7 uppercase letters, shuffled.
     */
    public function generate(): string;
}
