<?php
declare(strict_types=1);

namespace Ollieread\JWT\Claims;

use Carbon\CarbonImmutable;
use DateTimeImmutable;
use DateTimeInterface;
use Lcobucci\JWT\Token\RegisteredClaims;
use Ollieread\JWT\Contracts\IssuedAtAware;
use Ollieread\JWT\Contracts\JWTClaim;

/**
 * @implements \Ollieread\JWT\Contracts\JWTClaim<DateTimeImmutable>
 */
final class NotWithin implements JWTClaim, IssuedAtAware
{
    private readonly string $interval;

    private DateTimeInterface $issuedAt;

    public function __construct(string $interval)
    {
        $this->interval = $interval;
    }

    /**
     * Returns the name of the claim.
     *
     * @return lowercase-string
     */
    public function name(): string
    {
        return RegisteredClaims::NOT_BEFORE;
    }

    /**
     * Returns the value of the claim.
     *
     * @return \DateTimeImmutable
     */
    public function value(): DateTimeImmutable
    {
        return CarbonImmutable::createFromInterface($this->issuedAt)
                              ->modify($this->interval);
    }

    public function setIssuedAt(DateTimeInterface $issuedAt): void
    {
        $this->issuedAt = $issuedAt;
    }
}
