<?php
declare(strict_types=1);

namespace Ollieread\JWT\Exceptions;

use Ollieread\JWT\Contracts\JWTClaim;
use RuntimeException;

final class CustomClaimException extends RuntimeException
{
    public static function invalid(string $class): self
    {
        return new self(sprintf('The JWT custom claim "%s" must implement "%s".', $class, JWTClaim::class));
    }

    public static function unresolvable(string $class): self
    {
        return new self(sprintf('The JWT custom claim "%s" cannot be resolved.', $class));
    }
}
