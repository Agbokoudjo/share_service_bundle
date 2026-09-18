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

namespace Wlindabla\ShareServiceBundle\Form;

use Symfony\Component\Form\FormInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Extracts and translates Symfony Form validation errors into a flat,
 * field-indexed array, recursing into nested (child) forms.
 *
 * NOTE: this class was named `ProcessingErrorFormHandle` in earlier
 * versions of this code; it has been renamed to `ProcessingErrorFormHandler`
 * for consistency with the rest of the codebase. Update your imports and
 * service references accordingly when upgrading.
 *
 * @author AGBOKOUDJO Franck <internationaleswebservices@gmail.com>
 */
final class ProcessingErrorFormHandler
{
    public function __construct(private readonly TranslatorInterface $translator)
    {
    }

    /**
     * @return array<string, list<string>> Translated error messages, indexed by field name (dot-notation for nested forms).
     */
    public function extractViolations(
        FormInterface $form,
        ?string $domain = null,
        ?string $locales = null,
    ): array {
        return $this->getErrorMessages($form, $domain, $locales);
    }

    /**
     * @return array<string, list<string>>
     */
    private function getErrorMessages(
        FormInterface $form,
        ?string $domain = null,
        ?string $locales = null,
        string $parent = '',
    ): array {
        $errors = [];

        foreach ($form->getErrors(true) as $error) {
            $fieldName = $parent ?: $form->getName();

            if (!isset($errors[$fieldName])) {
                $errors[$fieldName] = [];
            }

            $errors[$fieldName][] = $this->translator->trans(
                $error->getMessage(),
                $error->getMessageParameters(),
                $domain,
                $locales,
            );
        }

        // Recurse into children.
        foreach ($form->all() as $child) {
            // Only when the child has errors, or is a sub-form that might contain some.
            if (!$child->isValid() || $child->count() > 0) {
                $childName = $child->getName();
                $fullName = $parent !== '' ? $parent . '.' . $childName : $childName;
                $childErrors = $this->getErrorMessages($child, $domain, $locales, $fullName);

                if (!empty($childErrors)) {
                    foreach ($childErrors as $key => $messages) {
                        if (!isset($errors[$key])) {
                            $errors[$key] = [];
                        }

                        $errors[$key] = array_merge($errors[$key], $messages);
                    }
                }
            }
        }

        return $errors;
    }
}
