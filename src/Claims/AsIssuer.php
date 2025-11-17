<?php
declare(strict_types=1);

namespace Ollieread\JWT\Claims;

use Lcobucci\JWT\Token\RegisteredClaims;
use Ollieread\JWT\Contracts\JWTClaim;

/**
 * @implements \Ollieread\JWT\Contracts\JWTClaim<string|null>
 */
final readonly class AsIssuer implements JWTClaim
{
    private ?string $issuer;

    public function __construct(?string $issuer)
    {
        $this->issuer = $issuer;
    }

    /**
     * Returns the name of the claim.
     *
     * @return lowercase-string
     */
    public function name(): string
    {
        return RegisteredClaims::ISSUER;
    }

    /**
     * Returns the value of the claim.
     *
     * @return string|null
     */
    public function value(): ?string
    {
        return $this->issuer;
    }
}
