<?php
declare(strict_types=1);

namespace Ollieread\JWT;

use Carbon\CarbonImmutable;
use DateInterval;
use DateTimeImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Ollieread\JWT\Contracts\Generator;
use Ollieread\JWT\Contracts\GeneratorNameAware;
use Ollieread\JWT\Contracts\IssuedAtAware;
use Ollieread\JWT\Contracts\JWTClaim;
use Ollieread\JWT\Events\JWTTokenGenerated;
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
     * @param string|int $subject
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function generate(int|string $subject): UnencryptedToken
    {
        $builder  = $this->jwt->builder();
        $issuedAt = CarbonImmutable::now();

        if (is_string($subject) && empty($subject)) {
            throw new InvalidArgumentException('The subject cannot be an empty string.');
        }

        // Set the subject and issued at time.
        $builder->relatedTo((string)$subject)->issuedAt($issuedAt);

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

        $token = $builder->getToken(
            $this->jwt->signer(),
            $this->jwt->signingKey()
        );

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
                        throw new InvalidArgumentException('The audience claim cannot contain an empty string.');
                    }

                    $builder->permittedFor($audience);
                } else {
                    throw new InvalidArgumentException('The audience claim must be an array of strings, or be able to be cast to a string.');
                }
            }
        } else if (is_string($value) || is_int($value) || $value instanceof Stringable) {
            $value = (string)$value;

            if (empty($value)) {
                throw new InvalidArgumentException('The audience claim cannot contain an empty string.');
            }

            $builder->permittedFor((string)$value);
        } else {
            throw new InvalidArgumentException('The audience claim must be a string, or be able to be cast to a string.');
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
            throw new InvalidArgumentException(sprintf('The claim "%s" cannot be set.', $claim->name()));
        }

        if (is_string($value) || is_int($value) || $value instanceof Stringable) {
            $value = (string)$value;

            if (empty($value)) {
                throw new InvalidArgumentException(sprintf('The claim "%s" cannot be an empty string.', $claim->name()));
            }

            $builder->{$method}($value);
        } else {
            throw new InvalidArgumentException(
                sprintf('The claim "%s" must be a string or be able to be cast to a string.', $claim->name())
            );
        }
    }

    /**
     * Parse a JWT token.
     *
     * @param string $token
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function parse(string $token): UnencryptedToken
    {
        if (empty($token)) {
            throw new InvalidArgumentException('The token cannot be an empty string.');
        }

        /** @var \Lcobucci\JWT\UnencryptedToken $parsed */
        $parsed = $this->jwt->parser()->parse($token);

        return $parsed;
    }

    /**
     * @return \Generator<int, \Ollieread\JWT\Contracts\JWTClaim<mixed>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
                throw new InvalidArgumentException(sprintf('The claim class "%s" must implement "%s"', $class, JWTClaim::class));
            }

            $instance = $this->app->make($class, $params);

            if (! ($instance instanceof JWTClaim)) {
                throw new InvalidArgumentException(sprintf('The claim class "%s" must implement "%s"', $class, JWTClaim::class));
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

    private function fireTokenGeneratedEvent(UnencryptedToken $token): void
    {
        $this->dispatcher->dispatch(new JWTTokenGenerated($this->name(), $token));
    }
}
