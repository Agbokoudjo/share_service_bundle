<?php

declare(strict_types=1);

/*
 * This file is part of the project by AGBOKOUDJO Franck.
 *
 * (c) AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 * Company: INTERNATIONALES WEB APPS & SERVICES
 */

namespace Wlindabla\ShareServiceBundle\Serializer;

use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

/**
 * Facade simplifying the use of the Symfony Serializer.
 * Wraps the normalize/denormalize operations.
 *
 * Requires PHP 8.2+ (`readonly class` modifier).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
readonly class SerializerFacade
{
    public function __construct(
        public NormalizerInterface $normalizer,
        public DenormalizerInterface $denormalizer,
    ) {
    }

    /**
     * Normalizes an object into an array.
     *
     * @param mixed                $object  The object to normalize.
     * @param string|null          $format  The target format.
     * @param array<string, mixed> $context Additional context.
     * @return array<string, mixed>|string|int|float|bool|null
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): mixed
    {
        return $this->normalizer->normalize($object, $format, $context);
    }

    /**
     * Denormalizes data into an object of the given type.
     *
     * @template T
     * @param mixed                $data    The data to denormalize.
     * @param class-string<T>      $type    The target object type.
     * @param array<string, mixed> $context Additional context.
     * @return T
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }
}
