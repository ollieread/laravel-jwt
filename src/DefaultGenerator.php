<?php
declare(strict_types=1);

namespace Ollieread\JWT;

use Carbon\CarbonImmutable;
use DateInterval;
use DateTimeImmutable;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Ollieread\JWT\Contracts\Generator;
use Ollieread\JWT\Contracts\GeneratorNameAware;
use Ollieread\JWT\Contracts\IssuedAtAware;
use Ollieread\JWT\Contracts\JWTClaim;
use Ollieread\JWT\Events\JWTTokenGenerated;
use Ollieread\JWT\Events\JWTTokenGenerating;
use Ollieread\JWT\Exceptions\CustomClaimException;
use Ollieread\JWT\Exceptions\TokenGenerationException;
use Ollieread\JWT\Exceptions\TokenParsingException;
use Stringable;

final class DefaultGenerator implements Generator
{
    private readonly Application $app;

    private readonly Dispatcher $dispatcher;

    private readonly string $name;

    private readonly Configuration $jwt;

    private DateInterval|null $expiry;

    /**
     * @var list<class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>|array{0: class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>}>
     */
    private readonly array $claims;

    /**
     * @param \Illuminate\Foundation\Application                                                                                           $app
     * @param \Illuminate\Contracts\Events\Dispatcher                                                                                      $dispatcher
     * @param string                                                                                                                       $name
     * @param \Lcobucci\JWT\Configuration                                                                                                  $jwt
     * @param \DateInterval|null                                                                                                           $expiry
     * @param list<class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>|array{0:class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>}> $claims
     */
    public function __construct(
        Application       $app,
        Dispatcher        $dispatcher,
        string            $name,
        Configuration     $jwt,
        DateInterval|null $expiry,
        array             $claims
    )
    {
        $this->app        = $app;
        $this->dispatcher = $dispatcher;
        $this->name       = $name;
        $this->jwt        = $jwt;
        $this->expiry     = $expiry;
        $this->claims     = $claims;
    }

    /**
     * The name of the generator.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Generate a new JWT token for the provided subject.
     *
     * @param string|int|\Stringable $subject
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function generate(string|int|Stringable $subject): UnencryptedToken
    {
        // If it's stringable, manually call __toString() on it.
        if ($subject instanceof Stringable) {
            $subject = $subject->__toString();
        }

        // If it's a string, make sure it isn't empty.
        if (is_string($subject) && empty($subject)) {
            throw TokenGenerationException::invalidSubject();
        }

        // Cast to string.
        $subject = (string)$subject;

        // Fire the event to notify listeners that a token is being generated.
        $this->fireTokenGeneratingEvent($subject);

        $builder  = $this->jwt->builder();
        $issuedAt = CarbonImmutable::now();

        // Set the subject and issued at time.
        $builder->relatedTo($subject)->issuedAt($issuedAt);

        // If there's no expiry, set it to null, otherwise add the expiry
        // time to builder.
        if ($this->expiry === null) {
            $expiresAt = null;
        } else {
            $expiresAt = $issuedAt->add($this->expiry);

            $builder->expiresAt($expiresAt);
        }

        foreach ($this->collectClaims() as $claim) {
            // Some claims require runtime injection of values available
            // from within this class, so we do that first.
            $this->handleClaimInjection(
                $claim,
                $this->name,
                $issuedAt,
                $expiresAt
            );

            // Since the audience claim is a special class, as it's an array,
            // we handle that differently here, as some claims add to, and some
            // overwrite.
            if ($claim->name() === Token\RegisteredClaims::AUDIENCE) {
                $this->setAudienceClaim($builder, $claim);

                continue;
            }

            // If it's a custom claim, we just add it to the builder.
            if (! in_array($claim->name(), Token\RegisteredClaims::ALL, true)) {
                $builder->withClaim($claim->name(), $claim->value());
                continue;
            }

            // These are the only claims that can be set at generation time,
            // because the others like audience, subject, issued at and expires
            // at are all set above.
            $this->setRegisteredClaims($builder, $claim);
        }

        // Create the token object.
        $token = $builder->getToken(
            $this->jwt->signer(),
            $this->jwt->signingKey()
        );

        // Fire the event to notify listeners that a token has been generated.
        $this->fireTokenGeneratedEvent($token);

        return $token;
    }

    /**
     * @param \Lcobucci\JWT\Builder                    $builder
     * @param \Ollieread\JWT\Contracts\JWTClaim<mixed> $claim
     *
     * @return void
     */
    private function setAudienceClaim(Builder $builder, JWTClaim $claim): void
    {
        $value = $claim->value();

        if (is_array($value)) {
            // Ensure they're all strings.
            foreach ($value as $audience) {
                if (is_string($audience) || is_int($audience) || $audience instanceof Stringable) {
                    $audience = (string)$audience;

                    if (empty($audience)) {
                        throw TokenGenerationException::invalidAudience();
                    }

                    $builder->permittedFor($audience);
                } else {
                    throw TokenGenerationException::invalidAudience();
                }
            }
        } else if (is_string($value) || is_int($value) || $value instanceof Stringable) {
            $value = (string)$value;

            if (empty($value)) {
                throw TokenGenerationException::invalidAudience();
            }

            $builder->permittedFor((string)$value);
        } else {
            throw TokenGenerationException::invalidAudience();
        }
    }

    /**
     * @param \Lcobucci\JWT\Builder                    $builder
     * @param \Ollieread\JWT\Contracts\JWTClaim<mixed> $claim
     *
     * @return void
     */
    private function setRegisteredClaims(Builder $builder, JWTClaim $claim): void
    {
        if ($claim->name() === Token\RegisteredClaims::NOT_BEFORE) {
            $value = $claim->value();

            if (! ($value instanceof DateTimeImmutable)) {
                /** @phpstan-ignore argument.type */
                $value = CarbonImmutable::parse($value);
            }

            $builder->canOnlyBeUsedAfter($value);
        }

        if ($claim->name() === Token\RegisteredClaims::ISSUER) {
            $method = 'issuedBy';
            $value  = $claim->value();
        } else if ($claim->name() === Token\RegisteredClaims::ID) {
            $method = 'identifiedBy';
            $value  = $claim->value();
        } else {
            throw TokenGenerationException::restrictedClaim($claim->name());
        }

        if (is_string($value) || is_int($value) || $value instanceof Stringable) {
            $value = (string)$value;

            if (empty($value)) {
                throw TokenGenerationException::invalidClaim($claim->value());
            }

            $builder->{$method}($value);
        } else {
            throw TokenGenerationException::invalidClaim($claim->value());
        }
    }

    /**
     * Parse a JWT token.
     *
     * @param string $token
     * @param bool   $validate
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function parse(string $token, bool $validate = true): UnencryptedToken
    {
        if (empty($token)) {
            throw TokenParsingException::invalidString();
        }

        try {
            $parsed = $this->jwt->parser()->parse($token);
        } catch (CannotDecodeContent|Token\InvalidTokenStructure|Token\UnsupportedHeaderFound $e) {
            throw TokenParsingException::invalid($e);
        }

        if (! ($parsed instanceof UnencryptedToken)) {
            throw TokenParsingException::invalid();
        }

        if ($validate) {
            $this->checkTokenValidity($parsed);
        }

        return $parsed;
    }

    private function checkTokenValidity(UnencryptedToken $token): void
    {
        // First things first, check whether the token has expired, was issued
        // in the future, or if the minimum time hasn't passed.
        $now = CarbonImmutable::now();

        if ($token->isExpired($now)) {
            throw TokenParsingException::expired();
        }

        if (! $token->hasBeenIssuedBefore($now) || $token->isMinimumTimeBefore($now)) {
            throw TokenParsingException::notYet();
        }

        // Collect up all issuer and audience claims, so we can validate
        // against them.
        $allowedClaims = [
            Token\RegisteredClaims::ISSUER,
            Token\RegisteredClaims::AUDIENCE,
        ];

        $claimValues = [];

        foreach ($this->collectClaims() as $claim) {
            if (! in_array($claim->name(), $allowedClaims, true)) {
                continue;
            }

            if ($claim->name() === Token\RegisteredClaims::AUDIENCE) {
                $value = $claim->value();

                if (is_array($value)) {
                    $claimValues[$claim->name()] = array_merge($claimValues[$claim->name()] ?? [], $value);
                } else {
                    $claimValues[$claim->name()][] = $value;
                }
            } else {
                $claimValues[$claim->name()] = $claim->value();
            }
        }

        if (isset($claimValues[Token\RegisteredClaims::ISSUER]) && ! $token->hasBeenIssuedBy($claimValues[Token\RegisteredClaims::ISSUER])) {
            throw TokenParsingException::invalidIssuer($claimValues[Token\RegisteredClaims::ISSUER]);
        }

        if (isset($claimValues[Token\RegisteredClaims::AUDIENCE])) {
            $success = false;

            foreach ($claimValues[Token\RegisteredClaims::AUDIENCE] as $expectedAudience) {
                if ($token->isPermittedFor($expectedAudience)) {
                    $success = true;
                    break;
                }
            }

            if (! $success) {
                throw TokenParsingException::invalidAudience(...$claimValues[Token\RegisteredClaims::AUDIENCE]);
            }
        }
    }

    /**
     * @return \Generator<int, \Ollieread\JWT\Contracts\JWTClaim<mixed>>
     */
    private function collectClaims(): \Generator
    {
        foreach ($this->claims as $claim) {
            if (is_array($claim)) {
                $class  = array_shift($claim);
                $params = $claim;
            } else {
                $class  = $claim;
                $params = [];
            }

            /** @phpstan-ignore function.alreadyNarrowedType */
            if (! is_subclass_of($class, JWTClaim::class)) {
                throw CustomClaimException::invalid($class);
            }

            try {
                $instance = $this->app->make($class, $params);
            } catch (BindingResolutionException $e) {
                throw CustomClaimException::unresolvable($class);
            }

            if (! ($instance instanceof JWTClaim)) {
                throw CustomClaimException::invalid($class);
            }

            yield $instance;
        }
    }

    /**
     * @param \Ollieread\JWT\Contracts\JWTClaim<mixed> $instance
     * @param string                                   $name
     * @param \DateTimeImmutable                       $issuedAt
     * @param \DateTimeImmutable|null                  $expiresAt
     *
     * @return void
     */
    private function handleClaimInjection(
        JWTClaim               $instance,
        string                 $name,
        DateTimeImmutable      $issuedAt,
        DateTimeImmutable|null $expiresAt,
    ): void
    {
        if ($instance instanceof GeneratorNameAware) {
            $instance->setGeneratorName($name);
        }

        if ($instance instanceof IssuedAtAware) {
            $instance->setIssuedAt($issuedAt);
        }
    }

    private function fireTokenGeneratingEvent(string $subject): void
    {
        $this->dispatcher->dispatch(new JWTTokenGenerating($this->name(), $subject));
    }

    private function fireTokenGeneratedEvent(UnencryptedToken $token): void
    {
        $this->dispatcher->dispatch(new JWTTokenGenerated($this->name(), $token));
    }
}
