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

namespace Wlindabla\ShareServiceBundle\ArgumentResolver;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Controller\ValueResolverInterface;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadata;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionInterface;

/**
 * Decrypts encrypted identifiers (id, code, slug, ...) found as route
 * request attributes, before they reach the controller action.
 *
 * Configuration (services.yaml / wlindabla_share_service.yaml):
 *
 *   wlindabla_share_service:
 *       id_encryption:
 *           identity_key_collection: ['id', 'code', 'slug', 'userId', 'contactId', 'entityId']
 *
 * The first attribute name found on the request, in the configured order,
 * is treated as the identifier to decrypt. Values that are already numeric
 * or empty are left untouched (they are assumed to already be plain,
 * unencrypted values).
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class IdEncryptionRequestArgumentValueResolver implements ValueResolverInterface
{
    /**
     * @param list<non-empty-string> $identityKeyCollection Route attribute names to look for, in priority order.
     */
    public function __construct(
        private readonly IdEncryptionInterface $encryptionService,
        private readonly array $identityKeyCollection = ['id', 'code', 'slug'],
    ) {
    }

    public function resolve(Request $request, ArgumentMetadata $argument): iterable
    {
        // 1. Determine which identity attribute is present on the route ('id', 'code', ...).
        $identityKey = null;
        foreach ($this->identityKeyCollection as $parameterId) {
            if ($request->attributes->has($parameterId)) {
                $identityKey = $parameterId;
                break;
            }
        }

        // None of the configured attributes are present: defer to the next resolver.
        if (null === $identityKey) {
            return [];
        }

        $encodedValue = $request->attributes->get($identityKey);

        // Already a plain integer, or empty: nothing to decrypt, defer to the next resolver.
        if (is_numeric($encodedValue) || empty($encodedValue)) {
            return [];
        }

        try {
            // Decrypt the value (may return an int or a string/code).
            $decodedValue = $this->encryptionService->decryptId((string) $encodedValue);

            if (empty($decodedValue)) {
                throw new \RuntimeException(sprintf('Decoded identifier "%s" is invalid.', $identityKey));
            }

            // Replace the raw request attribute with the decrypted value.
            $request->attributes->set($identityKey, $decodedValue);

            if ($argument->getType() === Request::class) {
                return [$request];
            }

            // The controller argument name must match the attribute we just resolved.
            if ($argument->getName() !== $identityKey) {
                return [];
            }

            // Return an int when numeric (typical for IDs), the raw string otherwise (codes, slugs, ...).
            return [is_numeric($decodedValue) ? (int) $decodedValue : $decodedValue];
        } catch (\Throwable $e) {
            // Security: never leak the raw, unresolved value on failure.
            $request->attributes->set($identityKey, null);

            throw new NotFoundHttpException('Resource not found: invalid identifier.', $e);
        }
    }
}
