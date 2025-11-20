<?php
declare(strict_types=1);

namespace Ollieread\JWT\Events;

final readonly class JWTTokenGenerating
{
    public function __construct(
        public string $generator,
        public string $subject
    )
    {
    }
}
