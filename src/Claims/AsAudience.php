<?php
declare(strict_types=1);

namespace Ollieread\JWT\Claims;

use Lcobucci\JWT\Token\RegisteredClaims;
use Ollieread\JWT\Contracts\JWTClaim;

/**
 * @implements \Ollieread\JWT\Contracts\JWTClaim<list<string|null>>
 */
final readonly class AsAudience implements JWTClaim
{
    /**
     * @var list<string|null>
     */
    private array $audience;

    /**
     * @param list<string|null> $audience
     */
    public function __construct(array $audience)
    {
        $this->audience = $audience;
    }

    /**
     * Returns the name of the claim.
     *
     * @return lowercase-string
     */
    public function name(): string
    {
        return RegisteredClaims::AUDIENCE;
    }

    /**
     * Returns the value of the claim.
     *
     * @return list<string|null>
     */
    public function value(): array
    {
        return $this->audience;
    }
}
