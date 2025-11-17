<?php

namespace Ollieread\JWT\Contracts;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

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
     * @param string|int $subject
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function generate(string|int $subject): UnencryptedToken;

    /**
     * Parse a JWT token.
     *
     * @param string $token
     *
     * @return \Lcobucci\JWT\UnencryptedToken
     */
    public function parse(string $token): UnencryptedToken;
}
