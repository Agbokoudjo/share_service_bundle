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
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class IdEncryptionService implements IdEncryptionInterface
{
    /**
     * Raw (decoded) encryption key.
     */
    private readonly string $encryptionKey;

    public function __construct(string $encryptionKey)
    {
        // Decode from Base64 first.
        $decodedKey = base64_decode($encryptionKey, strict: true);

        if ($decodedKey === false) {
            throw new \InvalidArgumentException(
                'The encryption key must be valid Base64.',
            );
        }

        // The key must be exactly 32 bytes (256 bits).
        if (\strlen($decodedKey) !== 32) {
            throw new \InvalidArgumentException(
                \sprintf(
                    'The encryption key must be exactly 32 bytes (256 bits) after Base64 decoding, but %d bytes were provided.',
                    \strlen($decodedKey),
                ),
            );
        }

        $this->encryptionKey = $decodedKey;
    }

    public function encryptId(int|string $id): string
    {
        try {
            // Generate a random nonce.
            $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            // Encrypt the ID.
            $plaintext = (string) $id;
            $ciphertext = \sodium_crypto_secretbox(
                $plaintext, // The plaintext message to encrypt.
                $nonce,
                $this->encryptionKey, // 256-bit encryption key.
            ); // Authenticated encryption with a shared key.

            // Combine nonce + ciphertext, then encode.
            $encrypted = $nonce . $ciphertext;

            return $this->base64UrlEncode($encrypted);
        } catch (\Exception $e) {
            throw new \RuntimeException(
                \sprintf('Failed to encrypt the ID: %s', $e->getMessage()),
                0,
                $e,
            );
        }
    }

    public function decryptId(string $encryptedId): int|string
    {
        try {
            // Decode from URL-safe Base64.
            $encrypted = $this->base64UrlDecode($encryptedId);

            if ($encrypted === false) {
                throw new BadRequestHttpException('Invalid ID (Base64 decoding failed).');
            }

            // Split the nonce and ciphertext.
            $nonceSize = \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
            $nonce = substr($encrypted, 0, $nonceSize);
            $ciphertext = substr($encrypted, $nonceSize);

            if (\strlen($nonce) !== $nonceSize) {
                throw new BadRequestHttpException('Invalid ID (incorrect nonce).');
            }

            // Decrypt.
            $plaintext = \sodium_crypto_secretbox_open(
                $ciphertext,
                $nonce,
                $this->encryptionKey,
            );

            if ($plaintext === false) {
                throw new BadRequestHttpException('Invalid ID (decryption failed).');
            }

            return is_numeric($plaintext) ? (int) $plaintext : $plaintext;
        } catch (BadRequestHttpException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new BadRequestHttpException(
                \sprintf('Failed to decrypt the ID: %s', $e->getMessage()),
            );
        }
    }

    /**
     * URL-safe Base64 encoding.
     *
     * Replaces:
     * - "+" with "-"
     * - "/" with "_"
     * - "=" with "" (padding removed)
     */
    private function base64UrlEncode(string $data): string
    {
        $encoded = base64_encode($data);
        $encoded = strtr($encoded, '+/', '-_');

        return rtrim($encoded, '=');
    }

    /**
     * URL-safe Base64 decoding.
     */
    private function base64UrlDecode(string $data): string|false
    {
        // Restore padding if needed.
        $padding = 4 - (\strlen($data) % 4);
        if ($padding !== 4) {
            $data .= str_repeat('=', $padding);
        }

        // Restore standard Base64 alphabet.
        $data = strtr($data, '-_', '+/');

        return base64_decode($data, strict: true);
    }

    public static function generateEncryptionKey(): string
    {
        $key = random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

        return base64_encode($key);
    }
}
