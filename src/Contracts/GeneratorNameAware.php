<?php

namespace Ollieread\JWT\Contracts;

interface GeneratorNameAware
{
    public function setGeneratorName(string $name): void;
}
