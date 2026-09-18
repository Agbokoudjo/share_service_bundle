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

/**
 * Cryptographically secure password generator.
 *
 * Guarantees strong passwords containing at least:
 * - One uppercase letter
 * - One lowercase letter
 * - One digit
 * - One special symbol
 *
 * Uses cryptographically secure functions (random_int) to guarantee the
 * unpredictability of generated passwords.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package App\Application\Service
 */
final class RandomPasswordGenerator implements PasswordGeneratorInterface
{
    /**
     * Recommended minimum length for a secure password.
     */
    private const MIN_LENGTH = 16;

    private const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    private const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';

    private const DIGITS = '0123456789';

    private const SYMBOLS = '!@#$%^&*()-_+=~`[]{}\\|:;"\'<>,.?/';

    /**
     * Characters that may be visually ambiguous, excluded on request.
     */
    private const AMBIGUOUS_CHARS = '0O1lI|`\'";:,./\\';

    // At least one character of each type below must be present.
    private const REQUIRED_SETS = [
        self::UPPERCASE,
        self::LOWERCASE,
        self::DIGITS,
        self::SYMBOLS,
    ];

    /**
     * @throws InvalidArgumentException If the requested length is insufficient.
     */
    public function generate(
        int $length = self::MIN_LENGTH,
        bool $includeSymbols = true,
        bool $excludeAmbiguous = false,
    ): string {
        $this->validateLength($length);

        $sets = [
            self::UPPERCASE,
            self::LOWERCASE,
            self::DIGITS,
        ];

        if ($includeSymbols) {
            $sets[] = self::SYMBOLS;
        }

        $allChars = implode('', $sets);

        if ($excludeAmbiguous) {
            $allChars = str_replace(str_split(self::AMBIGUOUS_CHARS), '', $allChars);
        }

        $password = [];

        // 1. Guarantee at least one character of each required type.
        foreach (self::REQUIRED_SETS as $set) {
            $password[] = $this->getRandomCharFromSet($set);
        }

        // 2. Fill the rest with random characters.
        $remainingLength = $length - count(self::REQUIRED_SETS);
        for ($i = 0; $i < $remainingLength; $i++) {
            $password[] = $this->getRandomCharFromSet($allChars);
        }

        // 3. Shuffle securely.
        return $this->secureShuffle($password);
    }

    /**
     * Picks a random character from a given character set, securely.
     *
     * Uses random_int(), which is cryptographically secure, unlike rand()
     * or mt_rand().
     *
     * @param string $set Character set (e.g. 'ABCD', '0123456789').
     * @return string A single character picked at random.
     *
     * @throws \Exception If random_int() fails (insufficient entropy source).
     *
     * @example
     *  $char = $this->getRandomCharFromSet('0123456789'); // Returns '5', '0', '9', etc.
     *  $char = $this->getRandomCharFromSet('!@#$%^&*');   // Returns '@', '&', '#', etc.
     */
    private function getRandomCharFromSet(string $set): string
    {
        $setLength = strlen($set);

        if ($setLength === 0) {
            throw new InvalidArgumentException('The character set cannot be empty.');
        }

        $randomIndex = random_int(0, $setLength - 1);

        return $set[$randomIndex];
    }

    /**
     * Shuffles an array of characters in a cryptographically secure way.
     *
     * Uses the Fisher-Yates algorithm with random_int() instead of
     * str_shuffle(), which is not cryptographically secure.
     *
     * @param array<int, string> $characters Characters to shuffle.
     * @return string The shuffled string.
     *
     * @throws \Exception If random_int() fails.
     */
    private function secureShuffle(array $characters): string
    {
        $count = count($characters);

        // Fisher-Yates shuffle (cryptographically secure).
        for ($i = $count - 1; $i > 0; $i--) {
            $j = random_int(0, $i);

            $tmpChar = $characters[$i];
            [$characters[$i], $characters[$j]] = [$characters[$j], $tmpChar];
        }

        return implode('', $characters);
    }

    /**
     * Validates that the requested password length is sufficient.
     *
     * @throws InvalidArgumentException If the length is insufficient.
     */
    private function validateLength(int $length): void
    {
        if ($length < self::MIN_LENGTH) {
            throw new InvalidArgumentException(
                sprintf(
                    'The password length must be at least %d characters. Received: %d',
                    self::MIN_LENGTH,
                    $length,
                ),
            );
        }
    }
}
