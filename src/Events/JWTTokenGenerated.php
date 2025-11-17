<?php
declare(strict_types=1);

namespace Ollieread\JWT\Events;

use Lcobucci\JWT\UnencryptedToken;

final readonly class JWTTokenGenerated
{
    public function __construct(
        public string           $generator,
        public UnencryptedToken $token
    )
    {
    }
}
