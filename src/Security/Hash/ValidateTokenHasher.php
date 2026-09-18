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

namespace Wlindabla\ShareServiceBundle\Security\Hash;

use InvalidArgumentException;

final class ValidateTokenHasher
{
    /**
     * Minimum acceptable length for a token.
     */
    private const MIN_TOKEN_LENGTH = 8;

    /**
     * Validates that a plaintext token is acceptable.
     *
     * @throws InvalidArgumentException If the token is invalid.
     */
    public static function validateToken(string $plainToken): void
    {
        if (strlen($plainToken) < self::MIN_TOKEN_LENGTH) {
            throw new InvalidArgumentException(
                sprintf(
                    'The token must contain at least %d characters. Received: %d',
                    self::MIN_TOKEN_LENGTH,
                    strlen($plainToken),
                ),
            );
        }
    }

    /**
     * Validates that a hash has the expected format.
     *
     * @throws InvalidArgumentException If the hash is invalid.
     */
    public static function validateHash(string $hashedToken): void
    {
        if (empty($hashedToken)) {
            throw new InvalidArgumentException('The hash cannot be empty.');
        }

        if (!str_starts_with($hashedToken, '$')) {
            throw new InvalidArgumentException('Invalid hash format.');
        }
    }
}
