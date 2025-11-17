<?php

namespace Ollieread\JWT\Contracts;

use DateTimeInterface;

interface IssuedAtAware
{
    public function setIssuedAt(DateTimeInterface $issuedAt): void;
}
