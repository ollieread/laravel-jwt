<?php
declare(strict_types=1);

namespace Ollieread\JWT\Claims;

use Lcobucci\JWT\Token\RegisteredClaims;
use Ollieread\JWT\Contracts\GeneratorNameAware;
use Ollieread\JWT\Contracts\JWTClaim;

/**
 * @implements \Ollieread\JWT\Contracts\JWTClaim<string>
 */
final class GeneratorNameAsIssuer implements JWTClaim, GeneratorNameAware
{
    private string $generatorName;

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
     * @return string
     */
    public function value(): string
    {
        return $this->generatorName;
    }

    public function setGeneratorName(string $name): void
    {
        $this->generatorName = $name;
    }
}
