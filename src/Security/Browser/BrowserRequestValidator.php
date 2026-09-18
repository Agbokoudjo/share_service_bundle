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

namespace Wlindabla\ShareServiceBundle\Security\Browser;

use Symfony\Component\HttpFoundation\Request;

/**
 * Advanced browser-request validator.
 *
 * Detects and blocks:
 * - curl, wget, python-requests, httpie, postman
 * - Pentest tools (Burp, ZAProxy, sqlmap, nikto, etc.)
 * - Bots and crawlers outside the allowed scope
 * - Simulated browsers (inconsistent headers)
 *
 * NOTE: this validator only inspects 100% spoofable headers (User-Agent,
 * Accept-*, Sec-Fetch-*). It filters out noise (untargeted scripts) but
 * does NOT, on its own, constitute a security boundary against a targeted
 * attacker — combine it with {@see BrowserChallengeSigner} (JS proof), the
 * consuming application's native login throttling, and rate limiters.
 *
 * Requires PHP 8.3+ (typed class constants below).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class BrowserRequestValidator
{
    /**
     * Legitimate crawlers allowed only on PUBLIC pages (link previews from
     * WhatsApp/LinkedIn/Slack/Twitter shared outside of admin areas). Never
     * allowed on the 'sensitive' path.
     */
    private const array ALLOWED_CRAWLERS = [
        'bot/', 'crawler', 'spider', 'scraper', 'slurp',
        'googlebot', 'bingbot', 'yandexbot', 'semrushbot', 'ahrefsbot',
        'facebookexternalhit', 'twitterbot', 'linkedinbot', 'slackbot',
        'whatsapp', 'applebot', 'petalbot',
    ];

    /**
     * Pentest tools blocked even on public pages.
     */
    private const array BLOCKED_PENTEST_TOOLS = [
        'burpsuite', 'burp', 'zaproxy', 'owasp', 'nmap', 'masscan',
        'sqlmap', 'nikto', 'nessus', 'metasploit', 'wpscan',
        'dirbuster', 'gobuster', 'nuclei', 'hydra', 'ffuf',
    ];

    /**
     * User agents of automated HTTP clients/tools (curl, wget, scripts, ...).
     */
    private const array BLOCKED_USER_AGENTS = [
        'curl', 'wget', 'python-requests', 'httpie', 'postman', 'insomnia', 'paw/',
        'java/', 'python/', 'python-urllib', 'ruby', 'perl', 'node.js', 'node-fetch',
        'axios/', 'go-http-client', 'okhttp', 'zgrab', 'golang', 'libwww-perl',
        'php/', 'guzzlehttp',
    ];

    /**
     * Headers mandatorily present in any real browser request.
     */
    private const array REQUIRED_BROWSER_HEADERS = [
        'Accept', 'Accept-Language', 'Accept-Encoding', 'User-Agent',
    ];

    /**
     * Default trusted IPs exempt from all validation, used when none are
     * injected via the constructor. Prefer injecting real values from
     * configuration (`wlindabla_share_service.trusted_ips`) rather than
     * relying on this fallback.
     */
    private const array DEFAULT_TRUSTED_IPS = [
        '127.0.0.1',
        '::1',
    ];

    /**
     * @param list<string> $trustedIps IPs exempt from all checks (monitoring, CI/CD, internal VPS).
     *                                 Defaults to {@see self::DEFAULT_TRUSTED_IPS} when not provided.
     */
    public function __construct(
        private readonly array $trustedIps = self::DEFAULT_TRUSTED_IPS,
    ) {
    }

    public function isValidPublicRequest(Request $request): bool
    {
        if ($this->isTrustedIp($request)) {
            return true;
        }

        $ua = $request->headers->get('User-Agent', '');
        $uaLower = strtolower($ua);

        if (empty($ua)) {
            return false;
        }

        foreach (self::BLOCKED_PENTEST_TOOLS as $tool) {
            if (str_contains($uaLower, $tool)) {
                return false;
            }
        }

        foreach (self::ALLOWED_CRAWLERS as $crawler) {
            if (str_contains($uaLower, $crawler)) {
                return true;
            }
        }

        foreach (self::BLOCKED_USER_AGENTS as $blocked) {
            if (str_contains($uaLower, strtolower($blocked))) {
                return false;
            }
        }

        return true;
    }

    public function isValidBrowserRequest(Request $request): bool
    {
        if ($this->isTrustedIp($request)) {
            return true;
        }

        if (!$this->hasValidUserAgent($request)) {
            return false;
        }
        if (!$this->hasRequiredBrowserHeaders($request)) {
            return false;
        }
        if (!$this->isUserAgentLanguageConsistent($request)) {
            return false;
        }
        if (!$this->isUserAgentEncodingConsistent($request)) {
            return false;
        }
        if (!$this->hasValidBrowserCharacteristics($request)) {
            return false;
        }
        if ($this->isSimulatedBrowser($request)) {
            return false;
        }

        return true;
    }

    public function getBlockReasonCode(Request $request): string
    {
        if ($this->isTrustedIp($request)) {
            return 'TRUSTED_IP';
        }
        if (!$this->hasValidUserAgent($request)) {
            return 'INVALID_USER_AGENT';
        }
        if (!$this->hasRequiredBrowserHeaders($request)) {
            return 'MISSING_REQUIRED_HEADERS';
        }
        if (!$this->isUserAgentLanguageConsistent($request)) {
            return 'ACCEPT_LANGUAGE_INVALID';
        }
        if (!$this->isUserAgentEncodingConsistent($request)) {
            return 'ACCEPT_ENCODING_INVALID';
        }
        if (!$this->hasValidBrowserCharacteristics($request)) {
            return 'INVALID_REQUEST_CHARACTERISTICS';
        }
        if ($this->isSimulatedBrowser($request)) {
            return 'SIMULATED_BROWSER_DETECTED';
        }

        return 'UNKNOWN';
    }

    /**
     * Returns a human-readable diagnostic message in English.
     *
     * NOTE: these are diagnostic/log messages, not end-user facing UI
     * text. If you need to display a message to end users, translate
     * {@see self::getBlockReasonCode()} through Symfony's Translator with
     * your own message catalogue instead of using this string directly.
     */
    public function getBlockReasonMessage(Request $request): string
    {
        $ua = $request->headers->get('User-Agent', '');

        if (empty($ua)) {
            return 'Request rejected: missing User-Agent. Access restricted to browsers.';
        }

        if (!$this->hasValidUserAgent($request)) {
            return sprintf(
                'Request rejected: User-Agent "%s" not allowed. Access restricted to browsers.',
                mb_substr($ua, 0, 80),
            );
        }

        if (!$this->hasRequiredBrowserHeaders($request)) {
            return 'Request rejected: required headers are missing. Access restricted to browsers.';
        }

        if ($this->isSimulatedBrowser($request)) {
            return 'Simulated browser detected. Access denied.';
        }

        return 'Request rejected: invalid request characteristics. Access restricted to browsers.';
    }

    private function isTrustedIp(Request $request): bool
    {
        $ip = $request->getClientIp();

        return $ip !== null && in_array($ip, $this->trustedIps, true);
    }

    private function hasValidUserAgent(Request $request): bool
    {
        $userAgent = $request->headers->get('User-Agent', '');

        if (empty($userAgent)) {
            return false;
        }

        $uaLower = strtolower($userAgent);

        foreach (self::BLOCKED_USER_AGENTS as $blocked) {
            if (str_contains($uaLower, strtolower($blocked))) {
                return false;
            }
        }

        return (bool) preg_match(
            '/\b(chrome|chromium|firefox|safari|edg(e|\/)|opera|opr|trident|gecko)\b/i',
            $userAgent,
        );
    }

    private function hasRequiredBrowserHeaders(Request $request): bool
    {
        foreach (self::REQUIRED_BROWSER_HEADERS as $header) {
            if (!$request->headers->has($header)) {
                return false;
            }
        }

        return true;
    }

    private function isUserAgentLanguageConsistent(Request $request): bool
    {
        $acceptLanguage = $request->headers->get('Accept-Language', '');

        if (empty($acceptLanguage)) {
            return false;
        }

        if ($acceptLanguage === '*') {
            return true;
        }

        $languages = explode(',', $acceptLanguage);

        foreach ($languages as $lang) {
            $lang = trim($lang);

            if (empty($lang)) {
                continue;
            }

            if (
                !preg_match(
                    '/^[a-zA-Z]{1,8}'
                    . '(-[a-zA-Z]{4})?'
                    . '(-([a-zA-Z]{2}|\d{3}))?'
                    . '(-[a-zA-Z0-9]{5,8})*'
                    . '(\s*;\s*q=(0(\.\d{1,3})?|1(\.0{1,3})?))?'
                    . '$/',
                    $lang,
                )
            ) {
                return false;
            }
        }

        return true;
    }

    private function isUserAgentEncodingConsistent(Request $request): bool
    {
        $acceptEncoding = $request->headers->get('Accept-Encoding', '');

        if (empty($acceptEncoding)) {
            return false;
        }

        return stripos($acceptEncoding, 'gzip') !== false
            || stripos($acceptEncoding, 'deflate') !== false
            || stripos($acceptEncoding, 'br') !== false
            || stripos($acceptEncoding, 'zstd') !== false;
    }

    /**
     * NOTE: JSON login requests and fetch() calls issued from front-end
     * JavaScript do not always set X-Requested-With, so
     * isXmlHttpRequest() may return false for them. They are treated like
     * any other request under an "API or admin" path (Accept: text/html
     * is accepted there too — see the isApiOrAdminPath branch below).
     */
    private function hasValidBrowserCharacteristics(Request $request): bool
    {
        $accept = $request->headers->get('Accept', '');
        $path = $request->getPathInfo();

        $isXhr = $request->isXmlHttpRequest();
        $isApiOrAdminPath = str_starts_with($path, '/api/') || str_starts_with($path, '/admin');
        $hasReferer = $request->headers->has('Referer');
        $hasOrigin = $request->headers->has('Origin');

        if (!$isXhr && !$isApiOrAdminPath) {
            if (stripos($accept, 'text/html') === false) {
                return false;
            }
        }

        if ($isApiOrAdminPath && !$isXhr) {
            $validAccept = stripos($accept, 'application/json') !== false
                || stripos($accept, 'application/ld+json') !== false
                || stripos($accept, 'text/html') !== false
                || stripos($accept, '*/*') !== false;

            if (!$validAccept) {
                return false;
            }
        }

        if (
            in_array($request->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT'], true)
            && !str_starts_with($path, '/api/')
            && !$hasReferer
            && !$hasOrigin
        ) {
            return false;
        }

        return true;
    }

    private function isSimulatedBrowser(Request $request): bool
    {
        $secFetchSite = $request->headers->get('Sec-Fetch-Site');
        $secFetchMode = $request->headers->get('Sec-Fetch-Mode');
        $secFetchDest = $request->headers->get('Sec-Fetch-Dest');

        $hasFetchHeaders = $secFetchSite !== null && $secFetchMode !== null && $secFetchDest !== null;

        if ($hasFetchHeaders && !$this->areSecFetchHeadersCoherent($secFetchSite, $secFetchMode, $secFetchDest)) {
            return true;
        }

        $isApiPath = str_starts_with($request->getPathInfo(), '/api/');
        if (
            $request->cookies->count() === 0
            && $request->getMethod() === 'POST'
            && !$isApiPath
        ) {
            $hasReferer = $request->headers->has('Referer');
            $hasOrigin = $request->headers->has('Origin');

            if (!$hasReferer && !$hasOrigin) {
                return true;
            }
        }

        return false;
    }

    private function areSecFetchHeadersCoherent(string $site, string $mode, string $dest): bool
    {
        $validSites = ['cross-site', 'same-origin', 'same-site', 'none'];
        $validModes = ['cors', 'navigate', 'no-cors', 'same-origin', 'websocket'];
        $validDests = [
            'audio', 'audioworklet', 'document', 'embed', 'empty',
            'font', 'frame', 'iframe', 'image', 'manifest', 'object',
            'paintworklet', 'report', 'script', 'serviceworker',
            'sharedworker', 'style', 'track', 'video', 'worker', 'xslt',
        ];

        if (
            !in_array($site, $validSites, true)
            || !in_array($mode, $validModes, true)
            || !in_array($dest, $validDests, true)
        ) {
            return false;
        }

        if ($mode === 'navigate' && !in_array($dest, ['document', 'iframe', 'frame', 'embed', 'object'], true)) {
            return false;
        }

        if ($mode === 'cors' && $dest === 'document') {
            return false;
        }

        return true;
    }
}
