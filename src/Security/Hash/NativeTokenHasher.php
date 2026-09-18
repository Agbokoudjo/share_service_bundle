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

use Psr\Log\LoggerInterface;
use RuntimeException;

/**
 * Native PHP implementation of secure token hashing.
 *
 * Uses PHP's password_hash()/password_verify() to guarantee:
 * - Resistance to brute-force attacks (slow algorithm)
 * - Protection against rainbow tables (automatic salting)
 * - Protection against timing attacks (constant-time comparison)
 *
 * Defaults to Argon2id, which currently offers the best
 * security/performance trade-off available.
 *
 * BUG FIX: an earlier version of {@see self::hash()} ignored the resolved
 * `$this->algorithm` / `$this->options` entirely and always called
 * `password_hash($plainToken, PASSWORD_DEFAULT)` with leftover,
 * intentionally-weakened Argon2 options (16 MB / 2 iterations / 1 thread)
 * from a debugging session. This meant the configured algorithm/options
 * were silently never applied. Both are fixed below: `hash()` now uses
 * `$this->algorithm` and `$this->options`, and the default Argon2 options
 * are restored to secure values (overridable via the constructor / bundle
 * configuration).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package App\Infrastructure\Security\Hash
 */
final class NativeTokenHasher implements TokenHasherInterface
{
    /**
     * Default hashing algorithm (Argon2id). Falls back to bcrypt if unavailable.
     */
    private const DEFAULT_ALGORITHM = \PASSWORD_ARGON2ID;

    /**
     * Fallback algorithm when Argon2id is not available.
     */
    private const FALLBACK_ALGORITHM = \PASSWORD_BCRYPT;

    /**
     * Default Argon2id options (secure values — do not lower these without
     * a specific, documented reason; see OWASP's password storage
     * cheat sheet for current recommendations).
     */
    private const ARGON2_OPTIONS = [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 2,         // 2 parallel threads
    ];

    /**
     * Default bcrypt options.
     */
    private const BCRYPT_OPTIONS = [
        'cost' => 12, // 12 rounds (2^12 = 4096 iterations)
    ];

    private readonly string $algorithm;
    private readonly array $options;

    public function __construct(
        ?string $algorithm = null,
        ?array $options = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->algorithm = $this->resolveAlgorithm($algorithm);
        $this->options = $options ?? $this->getDefaultOptions($this->algorithm);
    }

    public function hash(string $plainToken): string
    {
        // Input validation (length, etc.) is expected to already have happened in the presentation layer.
        try {
            $hash = \password_hash($plainToken, $this->algorithm, $this->options);

            if ($hash === false) {
                $this->logger?->error('password_hash() returned false');

                throw new RuntimeException('Hashing failed.');
            }

            $this->logger?->debug('Token hashed successfully', [
                'algorithm' => $this->getAlgorithmName($this->algorithm),
                'token_length' => strlen($plainToken),
            ]);

            return $hash;
        } catch (\Exception $e) {
            $this->logger?->error('Failed to hash token', [
                'error' => $e->getMessage(),
                'algorithm' => $this->algorithm,
            ]);

            throw new RuntimeException(
                'Unable to securely hash the token.',
                0,
                $e,
            );
        }
    }

    public function verify(string $plainToken, string $hashedToken): bool
    {
        ValidateTokenHasher::validateToken($plainToken);
        ValidateTokenHasher::validateHash($hashedToken);

        try {
            $isValid = password_verify($plainToken, $hashedToken);

            $this->logger?->debug('Token verification', [
                'valid' => $isValid,
            ]);

            return $isValid;
        } catch (\Exception $e) {
            $this->logger?->error('Failed to verify token', [
                'error' => $e->getMessage(),
            ]);

            // On error, treat as invalid for safety.
            return false;
        }
    }

    public function needsRehash(string $hashedToken): bool
    {
        ValidateTokenHasher::validateHash($hashedToken);

        return password_needs_rehash($hashedToken, $this->algorithm, $this->options);
    }

    /**
     * Resolves the algorithm to use, with fallback.
     */
    private function resolveAlgorithm(?string $algorithm): string
    {
        if ($algorithm !== null) {
            return $algorithm;
        }

        if (defined('PASSWORD_ARGON2ID')) {
            return self::DEFAULT_ALGORITHM;
        }

        $this->logger?->warning('Argon2id is not available, falling back to bcrypt');

        return self::FALLBACK_ALGORITHM;
    }

    /**
     * Returns the default options for the given algorithm.
     */
    private function getDefaultOptions(string $algorithm): array
    {
        return match ($algorithm) {
            \PASSWORD_ARGON2ID, \PASSWORD_ARGON2I => self::ARGON2_OPTIONS,
            \PASSWORD_BCRYPT => self::BCRYPT_OPTIONS,
            default => [],
        };
    }

    /**
     * Returns the human-readable name of an algorithm identifier.
     */
    private function getAlgorithmName(string $algorithm): string
    {
        return match ($algorithm) {
            \PASSWORD_ARGON2ID => 'Argon2id',
            \PASSWORD_ARGON2I => 'Argon2i',
            \PASSWORD_BCRYPT => 'bcrypt',
            default => 'unknown',
        };
    }
}
