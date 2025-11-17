<?php
declare(strict_types=1);

namespace Ollieread\JWT\Claims;

use Illuminate\Container\Attributes\Config;
use Lcobucci\JWT\Token\RegisteredClaims;
use Ollieread\JWT\Contracts\JWTClaim;

/**
 * @implements \Ollieread\JWT\Contracts\JWTClaim<string>
 */
final readonly class AppUrlAsIssuer implements JWTClaim
{
    private string $appUrl;

    public function __construct(
        #[Config('app.url')] string $appUrl
    )
    {
        $this->appUrl = $appUrl;
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
     * @return string
     */
    public function value(): string
    {
        return $this->appUrl;
    }
}
