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
 * Builds a lightweight device fingerprint (User-Agent + Accept-Language),
 * meant to be used as an informational hint only — never as a security
 * key. The source of truth for any single-session policy should remain a
 * proper session identifier managed by the consuming application.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
trait DeviceFingerprintUserAgent
{
    protected function buildDeviceFingerprint(Request $request): string
    {
        $userAgent = $request->headers->get('User-Agent', '');
        $acceptLanguage = $request->headers->get('Accept-Language', '');

        return hash('sha256', $userAgent . '|' . $acceptLanguage);
    }
}
