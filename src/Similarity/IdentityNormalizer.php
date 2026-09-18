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
 */

namespace Wlindabla\ShareServiceBundle\Similarity;

/**
 * Unicode normalization shared between:
 *  - {@see IdentitySimilarityChecker} (fine-grained comparison in PHP)
 *  - any database column indexed for trigram search (e.g. PostgreSQL pg_trgm)
 *
 * Centralizing this logic avoids any divergence between what a GIN/trigram
 * index finds as candidates and what the PHP-side similarity service
 * ultimately confirms.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * @package <https://github.com/Agbokoudjo/>
 */
final class IdentityNormalizer
{
    public static function normalize(string $value): string
    {
        $value = trim($value);

        if ($value === '') {
            return '';
        }

        if (class_exists(\Normalizer::class)) {
            $decomposed = \Normalizer::normalize($value, \Normalizer::FORM_D);
            if ($decomposed !== false) {
                $decomposed = preg_replace('/\p{Mn}+/u', '', $decomposed) ?? $decomposed;
                $recomposed = \Normalizer::normalize($decomposed, \Normalizer::FORM_C);
                if ($recomposed !== false) {
                    $value = $recomposed;
                }
            }
        }

        $value = mb_strtolower($value, 'UTF-8');
        $value = preg_replace('/[^\p{L}\p{N}\s]+/u', ' ', $value) ?? $value;
        $value = preg_replace('/\s+/u', ' ', $value) ?? $value;

        return trim($value);
    }
}
