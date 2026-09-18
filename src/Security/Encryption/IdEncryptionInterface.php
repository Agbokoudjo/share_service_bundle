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

namespace Wlindabla\ShareServiceBundle\Security\Encryption;

use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * Encrypts and decrypts entity IDs.
 *
 * Uses sodium (libsodium) for secure symmetric encryption.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
interface IdEncryptionInterface
{
    /**
     * Encrypts an ID into URL-safe Base64.
     *
     * No "/" or "+" characters, to avoid conflicts with route paths.
     *
     * @param int|string $id The ID to encrypt.
     * @return string The encrypted ID, URL-safe Base64 encoded.
     */
    public function encryptId(int|string $id): string;

    /**
     * Decrypts an ID.
     *
     * @param string $encryptedId The Base64-encoded, encrypted ID.
     * @return int|string The original ID.
     *
     * @throws BadRequestHttpException If decryption fails.
     */
    public function decryptId(string $encryptedId): int|string;

    /**
     * Generates an encryption key.
     *
     * Use once to generate the key to store in your `.env` file.
     *
     * @return string The generated key (Base64).
     */
    public static function generateEncryptionKey(): string;
}
