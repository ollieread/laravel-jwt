<?php
declare(strict_types=1);

namespace Ollieread\JWT\Exceptions;

use RuntimeException;
use Throwable;

final class TokenParsingException extends RuntimeException
{
    public static function invalidString(): self
    {
        return new self('The JWT token must be a non-empty string.');
    }

    public static function invalid(?Throwable $previous = null): self
    {
        return new self('The JWT token provided is invalid.', previous: $previous);
    }

    public static function expired(): self
    {
        return new self('The JWT token provided has expired.');
    }

    public static function notYet(): self
    {
        return new self('The JWT token is not yet valid.');
    }

    public static function invalidIssuer(string $issuer): self
    {
        return new self(sprintf('The JWT token was not issued by "%s".', $issuer));
    }

    public static function invalidAudience(string ...$audience): self
    {
        if (count($audience) === 1) {
            return new self(sprintf('The JWT token was not intended for the audience "%s".', $audience[0]));
        }

        return new self(sprintf('The JWT token was not intended for the audiences "%s".', implode('", "', $audience)));
    }
}
