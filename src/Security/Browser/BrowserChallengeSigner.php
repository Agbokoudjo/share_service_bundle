<?php

declare(strict_types=1);

/*
 * This file is part of the project by AGBOKOUDJO Franck.
 *
 * (c) AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * Company: INTERNATIONALES WEB APPS & SERVICES
 */

namespace Wlindabla\ShareServiceBundle\Security\Browser;

use Symfony\Component\HttpFoundation\Request;

/**
 * Issues and verifies a "JavaScript execution proof" cookie.
 *
 * Principle: a real browser executes the `<script>` returned by a
 * challenge listener in the consuming application, which sets this signed
 * cookie and reloads the page. curl/wget/python-requests never execute
 * that script, so they stay stuck on the interstitial page and can never
 * reach the real content or submit a protected form.
 *
 * SECURITY NOTE: this is a mass-anti-bot / noise-reduction layer, not a
 * cryptographic proof against a targeted attacker who reads the served
 * HTML. The actual security boundary remains authentication + native
 * login throttling + rate limiters, applied on top of this signal.
 *
 * Requires PHP 8.3+ (typed class constants below).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class BrowserChallengeSigner
{
    public const string COOKIE_NAME = '__bvc';

    /** Cookie lifetime in seconds (12h), aligned with the typical remember_me / admin session lifetime. */
    private const int TTL_SECONDS = 43200;

    public function __construct(
        private readonly string $appSecret,
    ) {
    }

    public function issue(Request $request): string
    {
        $payload = sprintf(
            '%s|%d|%s',
            $this->fingerprint($request),
            time(),
            bin2hex(random_bytes(8)),
        );

        return base64_encode($payload) . '.' . $this->sign($payload);
    }

    public function verify(Request $request, ?string $cookieValue): bool
    {
        if ($cookieValue === null || !str_contains($cookieValue, '.')) {
            return false;
        }

        [$encodedPayload, $signature] = explode('.', $cookieValue, 2);
        $payload = base64_decode($encodedPayload, true);

        if ($payload === false) {
            return false;
        }

        if (!hash_equals($this->sign($payload), $signature)) {
            return false;
        }

        $parts = explode('|', $payload, 3);
        if (\count($parts) !== 3) {
            return false;
        }
        [$fingerprint, $issuedAt] = $parts;

        if ((time() - (int) $issuedAt) > self::TTL_SECONDS) {
            return false;
        }

        return hash_equals($fingerprint, $this->fingerprint($request));
    }

    private function sign(string $payload): string
    {
        return hash_hmac('sha256', $payload, $this->appSecret);
    }

    private function fingerprint(Request $request): string
    {
        return hash(
            'sha256',
            $request->headers->get('User-Agent', '') . '|' . $request->headers->get('Accept-Language', ''),
        );
    }
}
