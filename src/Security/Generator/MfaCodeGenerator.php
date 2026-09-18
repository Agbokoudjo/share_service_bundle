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

use Psr\Log\LoggerInterface;

/**
 * Generates the MFA code sent by email: 13 digits + 7 uppercase letters,
 * randomly shuffled (20 characters total).
 *
 * Letters that could be confused with digits (I, O) are excluded from the
 * alphabet, to avoid transcription errors when the user re-types the code.
 *
 * Shuffling itself uses random_int() (not shuffle(), which is not
 * cryptographically secure) via a Fisher-Yates sort.
 *
 * Requires PHP 8.3+ (typed class constants below).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package App\Infrastructure\Security\Generator
 */
final class MfaCodeGenerator implements MfaCodeGeneratorInterface
{
    private const string DIGITS = '0123456789';
    private const string LETTERS = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // Without I, O.

    public function __construct(
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function generate(): string
    {
        try {
            $chars = [];

            for ($i = 0; $i < self::DIGIT_COUNT; ++$i) {
                $chars[] = self::DIGITS[random_int(0, \strlen(self::DIGITS) - 1)];
            }

            for ($i = 0; $i < self::LETTER_COUNT; ++$i) {
                $chars[] = self::LETTERS[random_int(0, \strlen(self::LETTERS) - 1)];
            }

            // Fisher-Yates with random_int(): cryptographically secure shuffle.
            for ($i = \count($chars) - 1; $i > 0; --$i) {
                $j = random_int(0, $i);
                [$chars[$i], $chars[$j]] = [$chars[$j], $chars[$i]];
            }

            return implode('', $chars);
        } catch (\Exception $e) {
            $this->logger?->critical('Failed to generate the MFA code', [
                'error' => $e->getMessage(),
            ]);

            throw new \RuntimeException(
                'Unable to generate a secure MFA code. The system randomness source is unavailable.',
                0,
                $e,
            );
        }
    }
}
