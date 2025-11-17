<?php
declare(strict_types=1);

namespace Ollieread\JWT;

use Lcobucci\JWT\Signer;

enum Algorithm: string
{
    case HS256   = 'HS256';
    case HS384   = 'HS384';
    case HS512   = 'HS512';
    case BLAKE2B = 'BLAKE2B';
    case ES256   = 'ES256';
    case ES384   = 'ES384';
    case ES512   = 'ES512';
    case RS256   = 'RS256';
    case RS384   = 'RS384';
    case RS512   = 'RS512';
    case EdDSA   = 'EdDSA';

    public function signer(): Signer
    {
        return match ($this) {
            self::HS256   => new Signer\Hmac\Sha256(),
            self::HS384   => new Signer\Hmac\Sha384(),
            self::HS512   => new Signer\Hmac\Sha512(),
            self::BLAKE2B => new Signer\Blake2b(),
            self::ES256   => new Signer\Ecdsa\Sha256(),
            self::ES384   => new Signer\Ecdsa\Sha384(),
            self::ES512   => new Signer\Ecdsa\Sha512(),
            self::RS256   => new Signer\Rsa\Sha256(),
            self::RS384   => new Signer\Rsa\Sha384(),
            self::RS512   => new Signer\Rsa\Sha512(),
            self::EdDSA   => new Signer\Eddsa(),
        };
    }

    public function isSymmetrical(): bool
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512, self::BLAKE2B => true,
            default                                              => false,
        };
    }
}
