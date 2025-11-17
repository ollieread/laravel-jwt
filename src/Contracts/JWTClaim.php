<?php

namespace Ollieread\JWT\Contracts;

/**
 * @template TType of mixed
 */
interface JWTClaim
{
    /**
     * Returns the name of the claim.
     *
     * @return non-empty-lowercase-string
     */
    public function name(): string;

    /**
     * Returns the value of the claim.
     *
     * @return string|int|float|bool|null
     *
     * @phpstan-return TType
     * @psalm-return TType
     */
    public function value(): mixed;
}
