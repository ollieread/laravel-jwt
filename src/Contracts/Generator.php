<?php

namespace Ollieread\JWT\Contracts;

use Lcobucci\JWT\UnencryptedToken;
use Stringable;

interface Generator
{
    /**
     * The name of the generator.
     *
     * @return string
     */
    public function name(): string;

    /**
     * Generate a new JWT token for the provided subject.
     *
     * @param string|int|\Stringable $subject
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function generate(string|int|Stringable $subject): UnencryptedToken;

    /**
     * Parse a JWT token.
     *
     * @param string $token
     * @param bool   $validate
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function parse(string $token, bool $validate = true): UnencryptedToken;
}
