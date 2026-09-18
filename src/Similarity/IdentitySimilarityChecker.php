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
 * For more information, please feel free to contact the author.
 */

namespace Wlindabla\ShareServiceBundle\Similarity;

/**
 * Detects similarity between two textual identities.
 *
 * Business goal: during registration, for example, spot a possible fraud
 * attempt or a data-entry mistake (first/last name swap, typo, extra or
 * missing space/hyphen) by comparing a newly submitted identity against
 * one already on record.
 *
 * The service is fully alphabet-agnostic: accented Latin, Cyrillic,
 * Arabic, Greek, etc. All normalization and comparison logic relies on
 * Unicode-aware functions (mb_* and intl's \Normalizer), never on
 * ASCII-only functions (strtolower, the native levenshtein(), etc.) which
 * would corrupt multi-byte characters.
 *
 * Requires PHP 8.3+ (typed class constants below).
 */
final class IdentitySimilarityChecker
{
    /**
     * Default similarity threshold, expressed as a percentage (0-100).
     * Used when no value is injected via configuration.
     */
    public const float DEFAULT_SIMILARITY_THRESHOLD = 88.0;

    /**
     * Weight given to Jaro-Winkler in the composite score.
     * (1 - self::JARO_WINKLER_WEIGHT) is applied to the Levenshtein similarity.
     */
    private const float JARO_WINKLER_WEIGHT = 0.6;

    /**
     * Standard scaling factor of the Winkler algorithm (0.1 max, usual value).
     */
    private const float WINKLER_SCALING_FACTOR = 0.1;

    /**
     * Maximum common-prefix length taken into account by Winkler.
     */
    private const int WINKLER_MAX_PREFIX_LENGTH = 4;

    public function __construct(
        /**
         * Similarity threshold (0-100) above which two identities are
         * considered suspicious. Injectable from configuration:
         *
         *   wlindabla_share_service:
         *       identity_similarity_threshold: 88.0
         */
        private readonly float $similarityThreshold = self::DEFAULT_SIMILARITY_THRESHOLD,
    ) {
    }

    /**
     * Main entry point: compares two textual identities and reports
     * whether their resemblance exceeds the configured threshold.
     *
     * @param string $identityA e.g. "Last First" or "First Last" for the current submission.
     * @param string $identityB e.g. the identity already stored in the database.
     * @return bool true when a strong resemblance/suspicion is detected.
     */
    public function hasHighSimilarity(string $identityA, string $identityB): bool
    {
        $normalizedA = $this->normalize($identityA);
        $normalizedB = $this->normalize($identityB);

        // Trivial cases: empty strings, or strictly identical after normalization.
        if ($normalizedA === '' || $normalizedB === '') {
            return false;
        }

        if ($normalizedA === $normalizedB) {
            return true;
        }

        $score = $this->computeSimilarityScore($normalizedA, $normalizedB);

        return $score >= ($this->similarityThreshold / 100.0);
    }

    /**
     * Returns the raw similarity score (0.0 to 1.0), useful for logging,
     * debugging, or displaying a "suspicion level".
     */
    public function computeSimilarityScore(string $identityA, string $identityB): float
    {
        $normalizedA = $this->normalize($identityA);
        $normalizedB = $this->normalize($identityB);

        if ($normalizedA === '' || $normalizedB === '') {
            return 0.0;
        }

        $charsA = mb_str_split($normalizedA, 1, 'UTF-8');
        $charsB = mb_str_split($normalizedB, 1, 'UTF-8');

        $jaroWinklerScore = $this->jaroWinkler($charsA, $charsB);
        $levenshteinScore = $this->levenshteinSimilarity($charsA, $charsB);

        $characterLevelScore = (self::JARO_WINKLER_WEIGHT * $jaroWinklerScore)
            + ((1 - self::JARO_WINKLER_WEIGHT) * $levenshteinScore);

        // Jaro-Winkler and Levenshtein both reason at the character/position
        // level: a full word-order swap ("Franck Agbokoudjo" ->
        // "Agbokoudjo Franck") moves an entire word past the tolerance
        // window of both algorithms and collapses their score, even though
        // the two strings contain exactly the same letters, just
        // rearranged in blocks.
        //
        // A complementary, word-level signal is therefore added:
        // alphabetically sorting the words of each identity neutralizes
        // any ordering effect (last/first or first/last name become
        // identical once sorted), then the sorted versions are compared
        // with the same character-by-character algorithms.
        $wordOrderScore = $this->wordOrderInvariantScore($normalizedA, $normalizedB);

        // The final score is the MAXIMUM of the two approaches: each
        // captures a different type of error (typo/accent for the first,
        // word-order swap for the second), without either weakening the
        // other.
        return max($characterLevelScore, $wordOrderScore);
    }

    /**
     * Compares two already-normalized identities after sorting their words
     * alphabetically, to neutralize any ordering effect (first/last name
     * swap). Reuses the same character-by-character algorithms as
     * computeSimilarityScore(), applied here to the sorted versions.
     */
    private function wordOrderInvariantScore(string $normalizedA, string $normalizedB): float
    {
        $wordsA = array_filter(explode(' ', $normalizedA), static fn (string $word): bool => $word !== '');
        $wordsB = array_filter(explode(' ', $normalizedB), static fn (string $word): bool => $word !== '');

        // A word-level comparison only makes sense when both identities
        // contain the same NUMBER of words (otherwise this isn't a simple
        // swap, but a genuinely different name).
        if (\count($wordsA) < 2 || \count($wordsA) !== \count($wordsB)) {
            return 0.0;
        }

        sort($wordsA);
        sort($wordsB);

        $sortedA = implode(' ', $wordsA);
        $sortedB = implode(' ', $wordsB);

        $charsA = mb_str_split($sortedA, 1, 'UTF-8');
        $charsB = mb_str_split($sortedB, 1, 'UTF-8');

        $jaroWinklerScore = $this->jaroWinkler($charsA, $charsB);
        $levenshteinScore = $this->levenshteinSimilarity($charsA, $charsB);

        return (self::JARO_WINKLER_WEIGHT * $jaroWinklerScore)
            + ((1 - self::JARO_WINKLER_WEIGHT) * $levenshteinScore);
    }

    /**
     * Universal Unicode normalization, delegated to {@see IdentityNormalizer}
     * so that it shares EXACTLY the same logic as any indexed database
     * column (e.g. a trigram/GIN index) used to pre-select candidates.
     *
     * Normalization summary:
     *  1. Canonical decomposition (NFD) to separate letters from diacritics
     *     (Latin accents, Arabic harakat, Cyrillic marks, etc.).
     *  2. Removal of all combining marks (\p{Mn}).
     *  3. Canonical recomposition (NFC).
     *  4. Multi-byte lowercasing (mb_strtolower).
     *  5. Removal of punctuation/symbols (hyphens, apostrophes), keeping
     *     only letters (\p{L}) and digits (\p{N}).
     *  6. Collapsing of repeated whitespace and trimming.
     */
    private function normalize(string $value): string
    {
        return IdentityNormalizer::normalize($value);
    }

    /**
     * Jaro-Winkler distance adapted to UTF-8 character arrays (as produced
     * by mb_str_split), returning a similarity score between 0 and 1.
     *
     * @param list<string> $charsA
     * @param list<string> $charsB
     */
    private function jaroWinkler(array $charsA, array $charsB): float
    {
        $lengthA = \count($charsA);
        $lengthB = \count($charsB);

        if ($lengthA === 0 || $lengthB === 0) {
            return 0.0;
        }

        $matchDistance = (int) floor(max($lengthA, $lengthB) / 2) - 1;
        $matchDistance = max($matchDistance, 0);

        $matchedA = array_fill(0, $lengthA, false);
        $matchedB = array_fill(0, $lengthB, false);

        $matches = 0;
        for ($i = 0; $i < $lengthA; $i++) {
            $start = max(0, $i - $matchDistance);
            $end = min($i + $matchDistance + 1, $lengthB);

            for ($j = $start; $j < $end; $j++) {
                if ($matchedB[$j] || $charsA[$i] !== $charsB[$j]) {
                    continue;
                }
                $matchedA[$i] = true;
                $matchedB[$j] = true;
                $matches++;
                break;
            }
        }

        if ($matches === 0) {
            return 0.0;
        }

        // Count transpositions.
        $transpositions = 0;
        $pointerB = 0;
        for ($i = 0; $i < $lengthA; $i++) {
            if (!$matchedA[$i]) {
                continue;
            }
            while (!$matchedB[$pointerB]) {
                $pointerB++;
            }
            if ($charsA[$i] !== $charsB[$pointerB]) {
                $transpositions++;
            }
            $pointerB++;
        }
        $transpositions = (int) ($transpositions / 2);

        $jaro = (
            ($matches / $lengthA)
            + ($matches / $lengthB)
            + (($matches - $transpositions) / $matches)
        ) / 3;

        // Winkler bonus for a common prefix (useful for typos near the end of a word).
        $prefixLength = 0;
        $maxPrefix = min(self::WINKLER_MAX_PREFIX_LENGTH, $lengthA, $lengthB);
        for ($i = 0; $i < $maxPrefix; $i++) {
            if ($charsA[$i] !== $charsB[$i]) {
                break;
            }
            $prefixLength++;
        }

        return $jaro + ($prefixLength * self::WINKLER_SCALING_FACTOR * (1 - $jaro));
    }

    /**
     * Normalized similarity based on the Levenshtein distance, computed
     * character by character on arrays produced by mb_str_split (so it is
     * safe for any Unicode alphabet, unlike the native levenshtein()
     * function, which is strictly single-byte/ASCII).
     *
     * @param list<string> $charsA
     * @param list<string> $charsB
     */
    private function levenshteinSimilarity(array $charsA, array $charsB): float
    {
        $lengthA = \count($charsA);
        $lengthB = \count($charsB);

        if ($lengthA === 0 && $lengthB === 0) {
            return 1.0;
        }

        if ($lengthA === 0 || $lengthB === 0) {
            return 0.0;
        }

        $previousRow = range(0, $lengthB);

        for ($i = 1; $i <= $lengthA; $i++) {
            $currentRow = [$i];

            for ($j = 1; $j <= $lengthB; $j++) {
                $deletionCost = $previousRow[$j] + 1;
                $insertionCost = $currentRow[$j - 1] + 1;
                $substitutionCost = $previousRow[$j - 1] + ($charsA[$i - 1] === $charsB[$j - 1] ? 0 : 1);

                $currentRow[$j] = min($deletionCost, $insertionCost, $substitutionCost);
            }

            $previousRow = $currentRow;
        }

        $distance = $previousRow[$lengthB];
        $maxLength = max($lengthA, $lengthB);

        return 1 - ($distance / $maxLength);
    }
}
