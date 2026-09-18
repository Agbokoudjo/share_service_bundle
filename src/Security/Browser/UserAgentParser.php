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

/**
 * Lightweight HTTP User-Agent parser: extracts only the browser name, its
 * major version, and the OS. Deliberately minimal (no bot/device/rendering
 * engine detection) — sufficient for a login audit log.
 *
 * Requires PHP 8.3+ (typed class constants below).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package <https://github.com/Agbokoudjo/>
 */
final class UserAgentParser implements UserAgentParserInterface
{
    /**
     * Order matters: Chromium-based browsers (Edge, Opera, Samsung
     * Internet, Brave) all embed "Chrome/" and "Safari/" in their UA
     * string, so their specific signatures must be tested BEFORE "Chrome".
     * Likewise, Safari must be tested after Chrome (Chrome's UA also
     * contains "Safari/").
     *
     * @var array<string, string> regex pattern => display name
     */
    private const array BROWSER_PATTERNS = [
        '/Edg\/([\d.]+)/i'            => 'Edge',
        '/OPR\/([\d.]+)/i'            => 'Opera',
        '/SamsungBrowser\/([\d.]+)/i' => 'Samsung Internet',
        '/Brave\/([\d.]+)/i'          => 'Brave',
        '/Firefox\/([\d.]+)/i'        => 'Firefox',
        '/Chrome\/([\d.]+)/i'         => 'Chrome',
        '/Version\/([\d.]+).*Safari/i' => 'Safari',
        '/MSIE ([\d.]+)/i'            => 'Internet Explorer',
        '/Trident.*rv:([\d.]+)/i'     => 'Internet Explorer',
    ];

    /**
     * @var array<string, string> regex pattern => display OS name
     */
    private const array OS_PATTERNS = [
        '/Windows NT 10\.0/i' => 'Windows 10/11',
        '/Windows NT 6\.3/i'  => 'Windows 8.1',
        '/Windows NT 6\.2/i'  => 'Windows 8',
        '/Windows NT 6\.1/i'  => 'Windows 7',
        '/Windows/i'          => 'Windows',
        '/iPhone|iPad|iPod/i' => 'iOS',
        '/Mac OS X ([\d_]+)/i' => 'macOS',
        '/Android ([\d.]+)/i' => 'Android',
        '/Linux/i'            => 'Linux',
    ];

    public function parse(?string $rawUserAgent): ?string
    {
        $rawUserAgent = trim((string) $rawUserAgent);

        if ('' === $rawUserAgent) {
            return null;
        }

        $browser = $this->matchBrowser($rawUserAgent);
        $os = $this->matchOs($rawUserAgent);

        if (null === $browser && null === $os) {
            // Fallback: don't lose the information entirely, just truncate the raw string.
            return mb_substr($rawUserAgent, 0, 255);
        }

        return match (true) {
            null !== $browser && null !== $os => sprintf('%s on %s', $browser, $os),
            null !== $browser => $browser,
            default => $os,
        };
    }

    private function matchBrowser(string $userAgent): ?string
    {
        foreach (self::BROWSER_PATTERNS as $pattern => $name) {
            if (preg_match($pattern, $userAgent, $matches) === 1) {
                $version = $matches[1] ?? null;
                $majorVersion = $version ? explode('.', $version)[0] : null;

                return $majorVersion ? sprintf('%s %s', $name, $majorVersion) : $name;
            }
        }

        return null;
    }

    private function matchOs(string $userAgent): ?string
    {
        foreach (self::OS_PATTERNS as $pattern => $name) {
            if (preg_match($pattern, $userAgent) === 1) {
                return $name;
            }
        }

        return null;
    }
}
