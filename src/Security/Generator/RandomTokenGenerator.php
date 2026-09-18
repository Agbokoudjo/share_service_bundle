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

use InvalidArgumentException;
use Psr\Log\LoggerInterface;

/**
 * Cryptographically secure token generator.
 *
 * Uses random_bytes() to guarantee the unpredictability of generated
 * tokens. Tokens are hex-encoded for URL and database compatibility.
 *
 * NOTE: the logger is optional (nullable), unlike an earlier version of
 * this class that required it — a reusable library service should not
 * force a logging dependency on every consumer.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package App\Infrastructure\Security
 */
final class RandomTokenGenerator implements TokenGeneratorInterface
{
    /**
     * Minimum allowed token length (8 characters = 4 bytes).
     */
    private const MIN_LENGTH = 8;

    /**
     * Maximum allowed token length (256 characters = 128 bytes).
     */
    private const MAX_LENGTH = 256;

    public function __construct(
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function generate(int $length = self::DEFAULT_EMAIL_TOKEN_LENGTH): string
    {
        $this->validateLength($length);

        try {
            // 1. Compute the number of bytes needed.
            // bin2hex() doubles the length: 1 byte = 2 hex characters.
            $bytesNeeded = (int) ceil($length / 2);

            // 2. Generate cryptographically secure random bytes.
            $randomBytes = random_bytes($bytesNeeded);

            // 3. Convert to hexadecimal.
            $token = bin2hex($randomBytes);

            // 4. Truncate to the exact requested length.
            return substr($token, 0, $length);
        } catch (\Exception $e) {
            // Critical: the system's randomness source is compromised.
            $this->logger?->critical(
                'Failed to generate a cryptographic token',
                [
                    'error' => $e->getMessage(),
                    'requested_length' => $length,
                ],
            );

            throw new \RuntimeException(
                'Unable to generate a secure token. The system randomness source is unavailable.',
                0,
                $e,
            );
        }
    }

    /**
     * Validates that the requested length is within acceptable bounds.
     *
     * @throws InvalidArgumentException If the length is invalid.
     */
    private function validateLength(int $length): void
    {
        if ($length < self::MIN_LENGTH) {
            throw new InvalidArgumentException(
                sprintf(
                    'The token length must be at least %d characters. Received: %d',
                    self::MIN_LENGTH,
                    $length,
                ),
            );
        }

        if ($length > self::MAX_LENGTH) {
            throw new InvalidArgumentException(
                sprintf(
                    'The token length cannot exceed %d characters. Received: %d',
                    self::MAX_LENGTH,
                    $length,
                ),
            );
        }
    }
}
