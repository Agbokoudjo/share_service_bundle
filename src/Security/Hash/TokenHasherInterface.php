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

/**
 * Interface for the secure hashing of single-use tokens.
 *
 * Defines the contract for hashing and verifying tokens used for:
 * - Email confirmation
 * - Password reset
 * - Temporary session tokens
 * - CSRF tokens
 *
 * Uses slow hashing algorithms (bcrypt, argon2) to protect against
 * brute-force attacks.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
interface TokenHasherInterface
{
    /**
     * Hashes a plaintext token for secure storage in a database.
     *
     * The resulting hash must be resistant to:
     * - Brute force (slow algorithm)
     * - Rainbow tables (automatic salting)
     * - Timing attacks (constant-time comparison)
     *
     * @param string $plainToken The plaintext token to hash.
     * @return string The token hash, including salt and algorithm parameters.
     *
     * @throws \RuntimeException If hashing fails (insufficient memory, etc.).
     */
    public function hash(string $plainToken): string;

    /**
     * Checks whether a plaintext token matches the stored hash.
     *
     * Uses a constant-time comparison to avoid timing attacks. Compatible
     * with older hashes if the algorithm changes (automatic rehashing).
     *
     * @param string $plainToken  The plaintext token to verify.
     * @param string $hashedToken The hash stored in the database.
     * @return bool True if the token matches, false otherwise.
     */
    public function verify(string $plainToken, string $hashedToken): bool;

    /**
     * Checks whether a hash should be regenerated with more recent parameters.
     *
     * Useful for progressively migrating to more secure algorithms without
     * invalidating existing tokens.
     *
     * @param string $hashedToken The hash to check.
     * @return bool True if the hash should be regenerated, false otherwise.
     */
    public function needsRehash(string $hashedToken): bool;
}
