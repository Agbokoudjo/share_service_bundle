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
 * Interface for generating cryptographically secure tokens.
 *
 * Defines the contract for generating random tokens used for:
 * - Email confirmation
 * - Password reset
 * - 2FA verification
 * - CSRF tokens
 * - API tokens
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
interface TokenGeneratorInterface
{
    /**
     * Default recommended length for an email confirmation token.
     */
    public const DEFAULT_EMAIL_TOKEN_LENGTH = 32;

    /**
     * Default length for a password reset token.
     */
    public const DEFAULT_PASSWORD_RESET_TOKEN_LENGTH = 32;

    /**
     * Default length for an API token.
     */
    public const DEFAULT_API_TOKEN_LENGTH = 64;

    /**
     * Generates a cryptographically secure random token.
     *
     * The generated token uses hexadecimal characters (0-9, a-f), for
     * safe use in URLs and databases.
     *
     * @param int $length The desired token length in characters (minimum 1).
     * @return string The generated token, in hexadecimal.
     *
     * @throws \InvalidArgumentException If the length is invalid.
     * @throws \Exception If cryptographic generation fails.
     */
    public function generate(int $length = self::DEFAULT_EMAIL_TOKEN_LENGTH): string;
}
