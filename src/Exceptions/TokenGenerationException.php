<?php
declare(strict_types=1);

namespace Ollieread\JWT\Exceptions;

use RuntimeException;

final class TokenGenerationException extends RuntimeException
{
    public static function invalidSubject(): self
    {
        return new self('The JWT subject must be a non-empty string.');
    }

    public static function invalidAudience(): self
    {
        return new self(
            'The JWT audience must be a non-empty string, an array of non-empty strings, or be castable to a non-empty string.'
        );
    }

    public static function restrictedClaim(string $claim): self
    {
        return new self(sprintf('The JWT claim "%s" is restricted.', $claim));
    }

    public static function invalidClaim(string $claim): self
    {
        return new self(sprintf('The claim "%s" must be a non-empty string, or be castable to a non-empty string.', $claim));
    }
}
