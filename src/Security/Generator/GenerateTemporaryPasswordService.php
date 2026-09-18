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
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package App\Application\UseCase\CommandHandler\User
 */
final class GenerateTemporaryPasswordService
{
    /**
     * Length of the temporary password generated on account activation.
     */
    private const TEMPORARY_PASSWORD_LENGTH = 20;

    public function __construct(
        private readonly PasswordGeneratorInterface $passwordGenerator,
    ) {
    }

    /**
     * Generates a strong temporary password.
     *
     * Characteristics:
     * - Length: 20 characters
     * - Uppercase and lowercase letters
     * - Digits
     * - Special characters for extra strength
     * - Ambiguous characters excluded (0/O, 1/l/I)
     *
     * @return string The plaintext password.
     *
     * @throws \RuntimeException If generation fails.
     */
    public function generateTemporaryPassword(): string
    {
        try {
            $password = $this->passwordGenerator->generate(
                self::TEMPORARY_PASSWORD_LENGTH,
                true,  // Include symbols.
                true,  // Exclude ambiguous characters.
            );

            if (empty($password)) {
                throw new \RuntimeException('The password generator returned an empty string.');
            }

            return $password;
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Unable to generate a secure password: ' . $e->getMessage(),
                0,
                $e,
            );
        }
    }
}
