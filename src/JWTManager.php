<?php
declare(strict_types=1);

namespace Ollieread\JWT;

use Carbon\CarbonInterval;
use DateInterval;
use Illuminate\Config\Repository;
use Illuminate\Container\Attributes\Config;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Ollieread\JWT\Contracts\Generator;

final class JWTManager
{
    private readonly Application $app;

    private readonly Repository $config;

    /**
     * @var array<string, \Ollieread\JWT\Contracts\Generator>
     */
    private array $generators = [];

    /**
     * @param \Illuminate\Foundation\Application $app
     * @param array<string, mixed>               $config
     */
    public function __construct(
        Application            $app,
        #[Config('jwt')] array $config,
    )
    {
        $this->app    = $app;
        $this->config = new Repository($config);
    }

    public function get(string $name): Generator
    {
        return $this->generators[$name] ?? $this->resolve($name);
    }

    public function resolve(string $name): Generator
    {
        $configKey = 'generators.' . $name;

        /** @var array<string, mixed>|null $config */
        $config = $this->config->get($configKey);

        if ($config === null) {
            throw new InvalidArgumentException("No generator found for name: $name");
        }

        $config = $this->fillDefaultConfig($config);

        // Validate the configuration.
        $this->validateConfig($name, $config);

        // Resolve components.
        $algo   = $this->resolveAlgorithm($config);
        $expiry = $this->resolveExpiry($config);
        $driver = $config['driver'] ?? null;

        if ($algo->isSymmetrical()) {
            /**
             * @var array{key: string} $config
             */
            $jwt = $this->createSymmetricalConfiguration($algo, $config);
        } else {
            /**
             * @var array{key:array{signing:string, verification:string}} $config
             */
            $jwt = $this->createAsymmetricalConfiguration($algo, $config);
        }

        if (is_string($driver) && $driver !== 'default') {
            if (method_exists($this, $method = 'create' . ucfirst($driver) . 'Generator')) {
                $instance = $this->$method(
                    $name,
                    $jwt,
                    $expiry,
                    $config
                );

                if (! ($instance instanceof Generator)) {
                    throw new InvalidArgumentException("Driver [{$driver}] must return an instance of " . Generator::class);
                }

                return $this->generators[$name] = $instance;
            }

            throw new InvalidArgumentException("Driver [{$driver}] not supported.");
        }

        return $this->generators[$name] = $this->createDefaultGenerator(
            $name,
            $jwt,
            $expiry,
            $config
        );
    }


    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function fillDefaultConfig(array $config): array
    {
        // If there's no algorithm specified, use HS256 as default and use
        // the application key as its key.
        if (! isset($config['algo'])) {
            $config['algo'] = Algorithm::HS256;
            $config['key']  = $this->app['config']['app.key'];
        }

        // Set the default expiration time to 1 hour if not specified.
        $config['expiry'] ??= '3600';

        return $config;
    }


    /**
     * @param string               $name
     * @param array<string, mixed> $config
     *
     * @return void
     */
    private function validateConfig(string $name, array $config): void
    {
        $this->validateAlgorithmAndKey($name, $config);
        $this->validateExpiry($name, $config);
        $this->validateClaims($name, $config);
    }

    /**
     * @param string               $name
     * @param array<string, mixed> $config
     *
     * @return void
     */
    private function validateAlgorithmAndKey(string $name, array $config): void
    {
        if (! isset($config['algo'])) {
            throw new InvalidArgumentException('No algorithm set for JWT guard "' . $name . '".');
        }

        if (! in_array($config['algo'], Algorithm::cases(), true)) {
            throw new InvalidArgumentException('Invalid algorithm for JWT guard "' . $name . '".');
        }

        /** @var array{
         *     algo: string|\Ollieread\JWT\Algorithm,
         *     key?: mixed|array{signing:mixed, verification:mixed}
         * } $config
         */

        $algo = is_string($config['algo']) ? Algorithm::from($config['algo']) : $config['algo'];

        if ($algo->isSymmetrical()) {
            if (! isset($config['key']) || ! is_string($config['key'])) {
                throw new InvalidArgumentException('Invalid key set for JWT guard "' . $name . '".');
            }
        } else if (! isset($config['key']) || ! is_array($config['key']) || ! isset($config['key']['signing'], $config['key']['verification']) || ! is_string($config['key']['signing']) || ! is_string($config['key']['verification'])) {
            throw new InvalidArgumentException('Invalid public/private key pair set for JWT guard "' . $name . '".');
        }
    }

    /**
     * @param string               $name
     * @param array<string, mixed> $config
     *
     * @return void
     */
    private function validateExpiry(string $name, array $config): void
    {
        if (! is_int($config['expiry']) && ! is_string($config['expiry'])) {
            throw new InvalidArgumentException('Invalid expiry set for JWT guard "' . $name . '".');
        }
    }

    /**
     * @param string               $name
     * @param array<string, mixed> $config
     *
     * @return void
     */
    private function validateClaims(string $name, array $config): void
    {

    }

    /**
     * @param array<string, mixed> $config
     *
     * @return \Ollieread\JWT\Algorithm
     */
    private function resolveAlgorithm(array $config): Algorithm
    {
        $algo = $config['algo'] ?? null;

        if ($algo instanceof Algorithm) {
            return $algo;
        }

        if (is_string($algo)) {
            return Algorithm::from($algo);
        }

        throw new InvalidArgumentException('Invalid algorithm set for JWT guard.');
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return DateInterval|null
     * @throws \Exception
     */
    private function resolveExpiry(array $config): ?DateInterval
    {
        /** @var int|string|null $expiry */
        $expiry = $config['expiry'] ?? null;

        if ($expiry === null) {
            return null;
        }

        if (is_int($expiry)) {
            return CarbonInterval::seconds($expiry);
        }

        return new DateInterval($expiry);
    }

    private function createSigningKey(string $key): Key
    {
        if (str_starts_with($key, 'base64:')) {
            /** @phpstan-ignore argument.type */
            return Key\InMemory::base64Encoded(str_replace('base64:', '', $key));
        }

        if (str_starts_with($key, 'file:')) {
            /** @phpstan-ignore argument.type */
            return Key\InMemory::file(str_replace('file:', '', $key));
        }

        /** @phpstan-ignore argument.type */
        return Key\InMemory::plainText($key);
    }

    /**
     * @param \Ollieread\JWT\Algorithm $algo
     * @param array{key:string}        $config
     *
     * @return \Lcobucci\JWT\Configuration
     */
    private function createSymmetricalConfiguration(Algorithm $algo, array $config): Configuration
    {
        return Configuration::forSymmetricSigner(
            $algo->signer(),
            $this->createSigningKey($config['key'])
        );
    }

    /**
     * @param \Ollieread\JWT\Algorithm                              $algo
     * @param array{key:array{signing:string, verification:string}} $config
     *
     * @return \Lcobucci\JWT\Configuration
     */
    private function createAsymmetricalConfiguration(Algorithm $algo, array $config): Configuration
    {
        return Configuration::forAsymmetricSigner(
            $algo->signer(),
            $this->createSigningKey($config['key']['signing']),
            $this->createSigningKey($config['key']['verification']),
        );
    }

    /**
     * @param string                                                                                                                                      $name
     * @param \Lcobucci\JWT\Configuration                                                                                                                 $jwt
     * @param \DateInterval|null                                                                                                                          $expiry
     * @param array{claims?:list<class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>|array{0:class-string<\Ollieread\JWT\Contracts\JWTClaim<mixed>>}>} $config
     *
     * @return \Ollieread\JWT\DefaultGenerator
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function createDefaultGenerator(string $name, Configuration $jwt, ?DateInterval $expiry, array $config): DefaultGenerator
    {
        return new DefaultGenerator(
            $this->app,
            $this->app->make(Dispatcher::class),
            $name,
            $jwt,
            $expiry,
            $config['claims'] ?? []
        );
    }
}
