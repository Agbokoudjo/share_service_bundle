# wlindabla/share-service-bundle

A reusable Symfony library bundling the cross-cutting services you used to copy-paste from project to project: ID encryption, token/password generation & hashing, browser/bot request validation, asynchronous service-method dispatch over Messenger, identity similarity detection, form violation extraction, and a thin Serializer facade.

- PHP `>=8.3`
- Symfony `^6.4 | ^7.0 | ^8.0`
- `ext-sodium` required (ID encryption)

## Installation

```bash
composer require wlindabla/share-service-bundle
```

If your project does not use Symfony Flex, enable the bundle manually in `config/bundles.php`:

```php
return [
    // ...
    Wlindabla\ShareServiceBundle\WlindablaShareServiceBundle::class => ['all' => true],
];
```

## Configuration

Create `config/packages/wlindabla_share_service.yaml`:

```yaml
wlindabla_share_service:
    id_encryption:
        # Generate the key once:
        # php -r "require 'vendor/autoload.php'; echo \Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionService::generateEncryptionKey();"
        encryption_key: '%env(APP_ID_ENCRYPTION_KEY)%'
        identity_key_collection: ['id', 'code', 'slug']

    token_hasher:
        algorithm: null   # null = Argon2id if available, bcrypt fallback otherwise
        options: []       # password_hash() options; secure defaults are used otherwise

    identity_similarity_threshold: 88.0

    trusted_ips: ['127.0.0.1', '::1']

    async_method_dispatcher:
        transport: async_app_transport
        # Strict whitelist: only these FQCNs can be invoked from a queued message.
        allowed_services:
            - App\Infrastructure\Service\Mailing\PasswordResetMailerService
```

`IdEncryptionInterface` and its `ArgumentResolver` are only registered when `encryption_key` is set: a project that doesn't use that feature can leave the key `null` with no boot-time error.

---

## Services & usage examples

### 1. `Bus\EventBusInterface`

Framework-agnostic wrapper around Symfony's event dispatcher.

```php
use Wlindabla\ShareServiceBundle\Bus\EventBusInterface;

final class RegisterUserHandler
{
    public function __construct(private readonly EventBusInterface $eventBus)
    {
    }

    public function __invoke(RegisterUserCommand $command): void
    {
        // ... create the user ...

        $this->eventBus->dispatch(new UserRegisteredEvent($user->getId()));
    }
}
```

---

### 2. `Security\Encryption\IdEncryptionInterface`

Encrypts/decrypts entity IDs into a URL-safe string (libsodium `secretbox`), so you never expose raw database IDs in routes.

```php
use Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionInterface;

final class InvoiceController
{
    public function __construct(private readonly IdEncryptionInterface $idEncryption)
    {
    }

    public function show(int $invoiceId): Response
    {
        $encryptedId = $this->idEncryption->encryptId($invoiceId);

        // https://example.com/invoices/aZ9xK3...  instead of /invoices/4821
        return new RedirectResponse('/invoices/' . $encryptedId);
    }
}
```

Generate the encryption key once, and store it as `APP_ID_ENCRYPTION_KEY` in your `.env` / secrets vault:

```bash
php -r "require 'vendor/autoload.php'; echo \Wlindabla\ShareServiceBundle\Security\Encryption\IdEncryptionService::generateEncryptionKey();"
```

**Automatic decryption in controllers** — once configured, `IdEncryptionRequestArgumentValueResolver` transparently decrypts `id`/`code`/`slug` route attributes before your controller runs:

```php
#[Route('/invoices/{id}', name: 'invoice_show')]
public function show(int $id): Response
{
    // $id is already the decrypted, plain integer — nothing to do here.
    $invoice = $this->invoiceRepository->find($id);
    // ...
}
```

---

### 3. `Security\Generator\PasswordGeneratorInterface`

Cryptographically secure password generator (guarantees at least one uppercase, one lowercase, one digit, one symbol).

```php
use Wlindabla\ShareServiceBundle\Security\Generator\PasswordGeneratorInterface;

final class AdminAccountCreator
{
    public function __construct(private readonly PasswordGeneratorInterface $passwordGenerator)
    {
    }

    public function createAccount(): string
    {
        // 24 chars, symbols included, ambiguous chars (0/O, 1/l/I) excluded
        return $this->passwordGenerator->generate(24, includeSymbols: true, excludeAmbiguous: true);
    }
}
```

---

### 4. `Security\Generator\GenerateTemporaryPasswordService`

Ready-made 20-character temporary password generator (symbols included, ambiguous characters excluded) — typical use: account activation.

```php
use Wlindabla\ShareServiceBundle\Security\Generator\GenerateTemporaryPasswordService;

final class ActivateUserAccount
{
    public function __construct(
        private readonly GenerateTemporaryPasswordService $temporaryPassword,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ) {
    }

    public function activate(User $user): string
    {
        $plainPassword = $this->temporaryPassword->generateTemporaryPassword();

        $user->setPassword($this->passwordHasher->hashPassword($user, $plainPassword));

        // Return the plaintext password once, to be emailed to the user.
        return $plainPassword;
    }
}
```

---

### 5. `Security\Generator\MfaCodeGeneratorInterface`

Generates a 20-character MFA code (13 digits + 7 uppercase letters, shuffled) — meant to be emailed, never stored as plaintext.

```php
use Wlindabla\ShareServiceBundle\Security\Generator\MfaCodeGeneratorInterface;

final class SendMfaCodeHandler
{
    public function __construct(
        private readonly MfaCodeGeneratorInterface $mfaCodeGenerator,
        private readonly Security\Hash\TokenHasherInterface $tokenHasher,
        private readonly MailerInterface $mailer,
    ) {
    }

    public function send(User $user): void
    {
        $code = $this->mfaCodeGenerator->generate(); // e.g. "8K3P0912Q75...4T1N"

        $user->setMfaCodeHash($this->tokenHasher->hash($code));

        $this->mailer->send((new TemplatedEmail())
            ->to($user->getEmail())
            ->htmlTemplate('security/mfa_code.html.twig')
            ->context(['code' => $code]));
    }
}
```

---

### 6. `Security\Generator\TokenGeneratorInterface`

Cryptographically secure hexadecimal tokens — email confirmation, password reset, API tokens.

```php
use Wlindabla\ShareServiceBundle\Security\Generator\TokenGeneratorInterface;

final class RequestPasswordReset
{
    public function __construct(private readonly TokenGeneratorInterface $tokenGenerator)
    {
    }

    public function handle(User $user): string
    {
        $token = $this->tokenGenerator->generate(TokenGeneratorInterface::DEFAULT_PASSWORD_RESET_TOKEN_LENGTH);
        // 32-character hex token, e.g. "a1f9c3e7b2..."

        $user->setResetToken($token);
        $user->setResetTokenExpiresAt(new \DateTimeImmutable('+1 hour'));

        return $token;
    }
}
```

Other predefined lengths: `TokenGeneratorInterface::DEFAULT_EMAIL_TOKEN_LENGTH` (32), `TokenGeneratorInterface::DEFAULT_API_TOKEN_LENGTH` (64).

---

### 7. `Security\Hash\TokenHasherInterface`

Hashes and verifies single-use tokens (Argon2id by default, bcrypt fallback) — same idea as password hashing, applied to tokens/MFA codes.

```php
use Wlindabla\ShareServiceBundle\Security\Hash\TokenHasherInterface;

final class VerifyResetToken
{
    public function __construct(private readonly TokenHasherInterface $tokenHasher)
    {
    }

    public function verify(User $user, string $submittedToken): bool
    {
        if (!$this->tokenHasher->verify($submittedToken, $user->getResetTokenHash())) {
            return false;
        }

        // Optional: transparently rehash if the algorithm/cost has changed since storage.
        if ($this->tokenHasher->needsRehash($user->getResetTokenHash())) {
            $user->setResetTokenHash($this->tokenHasher->hash($submittedToken));
        }

        return true;
    }
}
```

---

### 8. `Security\Browser\UserAgentParserInterface`

Turns a raw `User-Agent` header into a readable label — typical use: login audit log.

```php
use Wlindabla\ShareServiceBundle\Security\Browser\UserAgentParserInterface;

final class LoginAuditLogger
{
    public function __construct(private readonly UserAgentParserInterface $userAgentParser)
    {
    }

    public function logSuccessfulLogin(User $user, Request $request): void
    {
        $device = $this->userAgentParser->parse($request->headers->get('User-Agent'));
        // e.g. "Chrome 128 on Windows 10/11"

        $this->auditLog->record($user, 'login_success', ['device' => $device]);
    }
}
```

---

### 9. `Security\Browser\BrowserRequestValidator`

Filters out curl/wget/python-requests/pentest tools/bots from real browser traffic — a noise-reduction layer, not a security boundary by itself (combine with rate limiting and native login throttling).

```php
use Wlindabla\ShareServiceBundle\Security\Browser\BrowserRequestValidator;

final class AntiAutomationListener
{
    public function __construct(private readonly BrowserRequestValidator $requestValidator)
    {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();

        if (!str_starts_with($request->getPathInfo(), '/admin')) {
            return; // Only guard sensitive areas here.
        }

        if (!$this->requestValidator->isValidBrowserRequest($request)) {
            $this->logger->warning($this->requestValidator->getBlockReasonMessage($request), [
                'code' => $this->requestValidator->getBlockReasonCode($request),
            ]);

            throw new AccessDeniedHttpException('Access restricted to browsers.');
        }
    }
}
```

For public pages that should still allow legitimate crawlers (link previews, SEO bots) but block pentest tools, use `isValidPublicRequest()` instead:

```php
if (!$this->requestValidator->isValidPublicRequest($request)) {
    throw new AccessDeniedHttpException();
}
```

If you don't want the default trusted IPs (`127.0.0.1`, `::1`), inject your own list via `wlindabla_share_service.trusted_ips` in the bundle configuration — it's wired automatically into the constructor.

---

### 10. `Security\Browser\BrowserChallengeSigner`

Issues/verifies a signed "JavaScript execution proof" cookie: a real browser executes a small script that sets this cookie and reloads; curl/wget/scripts never do.

```php
use Wlindabla\ShareServiceBundle\Security\Browser\BrowserChallengeSigner;

final class JsChallengeController
{
    public function __construct(private readonly BrowserChallengeSigner $challengeSigner)
    {
    }

    #[Route('/js-challenge', name: 'js_challenge')]
    public function challenge(Request $request): Response
    {
        $cookieValue = $this->challengeSigner->issue($request);

        $response = new Response('<script>document.location.reload();</script>');
        $response->headers->setCookie(Cookie::create(BrowserChallengeSigner::COOKIE_NAME, $cookieValue)
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withSameSite('lax'));

        return $response;
    }

    #[Route('/protected-form', name: 'protected_form')]
    public function protectedForm(Request $request): Response
    {
        $cookieValue = $request->cookies->get(BrowserChallengeSigner::COOKIE_NAME);

        if (!$this->challengeSigner->verify($request, $cookieValue)) {
            return $this->redirectToRoute('js_challenge');
        }

        // ... render the real form ...
    }
}
```

---

### 11. `Security\Browser\DeviceFingerprintUserAgent` (trait)

Builds a lightweight, informational-only device fingerprint (`User-Agent` + `Accept-Language`). Never use it as a security key.

```php
use Wlindabla\ShareServiceBundle\Security\Browser\DeviceFingerprintUserAgent;

final class RememberedDeviceService
{
    use DeviceFingerprintUserAgent;

    public function isKnownDevice(User $user, Request $request): bool
    {
        $fingerprint = $this->buildDeviceFingerprint($request);

        return in_array($fingerprint, $user->getKnownDeviceFingerprints(), true);
    }
}
```

---

### 12. `Messenger\QueueHandler\AsyncMethodDispatcherInterface`

Defers a service-method call to a Symfony Messenger worker, optionally delayed until a given date.

```php
use Wlindabla\ShareServiceBundle\Messenger\QueueHandler\AsyncMethodDispatcherInterface;

final class OrderConfirmationController
{
    public function __construct(private readonly AsyncMethodDispatcherInterface $dispatcher)
    {
    }

    public function confirm(Order $order): Response
    {
        // Runs asynchronously on the 'async_app_transport' worker.
        $this->dispatcher->dispatch(
            service: OrderMailerService::class,
            method: 'sendConfirmation',
            params: ['orderId' => $order->getId()],
        );

        // Or deferred to a specific date:
        $this->dispatcher->dispatch(
            service: OrderMailerService::class,
            method: 'sendReminderIfUnpaid',
            params: ['orderId' => $order->getId()],
            date: new \DateTimeImmutable('+3 days'),
        );

        return new Response('Order confirmed.');
    }
}
```

**Required configuration** — `OrderMailerService::class` must be explicitly whitelisted, or the handler refuses to invoke it:

```yaml
wlindabla_share_service:
    async_method_dispatcher:
        allowed_services:
            - App\Infrastructure\Service\Mailing\OrderMailerService
```

You never call `ServiceMethodMessageHandler` or `ServiceMethodMessage` directly — `AsyncMethodDispatcher` builds and dispatches the message for you; the handler runs automatically on the worker (`php bin/console messenger:consume async_app_transport`).

---

### 13. `Similarity\IdentitySimilarityChecker`

Detects likely duplicate/fraudulent identities (typos, accents, first/last name swaps) using a Jaro-Winkler + Levenshtein composite score, fully Unicode-aware.

```php
use Wlindabla\ShareServiceBundle\Similarity\IdentitySimilarityChecker;

final class DuplicateAccountGuard
{
    public function __construct(private readonly IdentitySimilarityChecker $similarityChecker)
    {
    }

    public function checkForDuplicate(string $submittedFullName, array $existingFullNames): ?string
    {
        foreach ($existingFullNames as $existingName) {
            if ($this->similarityChecker->hasHighSimilarity($submittedFullName, $existingName)) {
                return $existingName; // Flag for manual review.
            }
        }

        return null;
    }

    public function debugScore(string $a, string $b): float
    {
        return $this->similarityChecker->computeSimilarityScore($a, $b); // 0.0 to 1.0
    }
}
```

```php
$checker->hasHighSimilarity('Franck Agbokoudjo', 'Agbokoudjo Franck'); // true (word-order swap)
$checker->hasHighSimilarity('François Dupont', 'Francois Dupont');    // true (accent-insensitive)
$checker->hasHighSimilarity('Jean Martin', 'Paul Durand');            // false
```

Threshold is configurable globally (`wlindabla_share_service.identity_similarity_threshold`, default `88.0`), or per-instance if you build your own:

```php
$strictChecker = new IdentitySimilarityChecker(similarityThreshold: 95.0);
```

`Similarity\IdentityNormalizer` is the static Unicode-normalization helper used internally — reuse it directly if you need the exact same normalization on the database side (e.g. a trigram/GIN index):

```php
use Wlindabla\ShareServiceBundle\Similarity\IdentityNormalizer;

$normalized = IdentityNormalizer::normalize('Jérémie   O\'Connor'); // "jeremie o connor"
```

---

### 14. `Form\ProcessingErrorFormHandler`

Recursively extracts and translates Symfony Form validation errors into a flat, field-indexed array — handy for JSON API responses.

```php
use Wlindabla\ShareServiceBundle\Form\ProcessingErrorFormHandler;

final class RegistrationApiController
{
    public function __construct(private readonly ProcessingErrorFormHandler $formErrorHandler)
    {
    }

    #[Route('/api/register', methods: ['POST'])]
    public function register(Request $request, FormFactoryInterface $formFactory): JsonResponse
    {
        $form = $formFactory->create(RegistrationType::class);
        $form->submit($request->request->all());

        if (!$form->isValid()) {
            $errors = $this->formErrorHandler->extractViolations($form, domain: 'validators');
            // ['email' => ['This value is already used.'], 'address.city' => ['This value should not be blank.']]

            return new JsonResponse(['errors' => $errors], 422);
        }

        // ...
    }
}
```

---

### 15. `Serializer\SerializerFacade`

Thin wrapper around Symfony's `NormalizerInterface`/`DenormalizerInterface`, for when you only need normalize/denormalize without pulling in the full `SerializerInterface`.

```php
use Wlindabla\ShareServiceBundle\Serializer\SerializerFacade;

final class InvoiceExportService
{
    public function __construct(private readonly SerializerFacade $serializer)
    {
    }

    public function toArray(Invoice $invoice): array
    {
        return $this->serializer->normalize($invoice, context: ['groups' => ['invoice:read']]);
    }

    public function fromArray(array $data): Invoice
    {
        return $this->serializer->denormalize($data, Invoice::class);
    }
}
```

---

## Service reference table

| Interface | Default implementation | Purpose |
|---|---|---|
| `Bus\EventBusInterface` | `Bus\SymfonyEventBusAdapter` | Dispatch domain events, decoupled from Symfony |
| `Security\Encryption\IdEncryptionInterface` | `IdEncryptionService` | URL-safe Base64 ID encryption (sodium) |
| `Security\Generator\PasswordGeneratorInterface` | `RandomPasswordGenerator` | Strong password generation |
| `Security\Generator\TokenGeneratorInterface` | `RandomTokenGenerator` | Cryptographic hex tokens |
| `Security\Generator\MfaCodeGeneratorInterface` | `MfaCodeGenerator` | 13-digit + 7-letter MFA code |
| `Security\Hash\TokenHasherInterface` | `NativeTokenHasher` | Argon2id/bcrypt token hashing |
| `Security\Browser\UserAgentParserInterface` | `UserAgentParser` | Readable browser/OS extraction |
| — | `Security\Browser\BrowserRequestValidator` | Bot / automated HTTP tool detection |
| — | `Security\Browser\BrowserChallengeSigner` | JS-execution-proof cookie |
| `Messenger\QueueHandler\AsyncMethodDispatcherInterface` | `AsyncMethodDispatcher` | Deferred service-method calls via Messenger |
| — | `Similarity\IdentitySimilarityChecker` | Identity duplicate detection (Jaro-Winkler + Levenshtein) |
| — | `Form\ProcessingErrorFormHandler` | Recursive form violation extraction |
| — | `Serializer\SerializerFacade` | normalize/denormalize facade |

## License

MIT — AGBOKOUDJO Franck / INTERNATIONALES WEB APPS & SERVICES