# Laravel JWT

This package provides a simple way to generate JWT tokens in Laravel, without tying you to any specific purpose
or part of Laravel.
It has been created primarily to use in my JWT auth package, but it can be used for anything else that requires
JWTs.

Under the hood it uses the `lcobucci/jwt` package to generate the actual JWTs.
You can read more about it on their [website](https://lcobucci-jwt.readthedocs.io/en/latest/installation/).

## Features

The following is a list of features I want this package to provider.

- [x] JWT Generation
- [x] JWT Parsing
- [ ] JWT Refreshing
- [ ] JWT Revoking

## Installation

You can install this package via composer:

```bash
composer require ollieread/laravel-jwt
```

Once installed, you'll need to publish the config file:

```bash
php artisan vendor:publish --provider="Ollieread\JWT\JWTServiceProvider"
```

> [!NOTE]
> If you aren't using package auto-discovery, you'll need to add the service provider to the `providers` array in
> `config/app.php`.

## Configuration

Once published, the config will be available at `config/jwt.php`.
Inside this file there is a `generators` key, which
is where you define your JWT generators.
The process is similar to any other driver-based Laravel feature, except that at this time of writing there's only one
driver, and it's `default`.

Here is an example of a generator:

```php
'users' => [
    'algo'   => \Ollieread\JWT\Algorithm::HS256,
    'key'    => env('JWT_AUTH_KEY'),
    'claims' => [
        \Ollieread\JWT\Claims\AppNameAsIssuer::class,
        \Ollieread\JWT\Claims\AppNameInAudience::class,
        [\Ollieread\JWT\Claims\NotWithin::class, '1 hour'],
    ],
],
```

### Algorithm

Every generator requires an algorithm, which is specified using the `algo` key.
If one isn't present, the default algorithm will be used, which is `HS256`.
Algorithms used the `\Ollieread\JWT\Algorithm` enum and are either symmetric or asymmetric, with asymmetric
requiring two keys, and symmetric requiring one.

#### Symmetric algorithms

- `HS256`
- `HS384`
- `HS512`
- `BLAKE2B`

#### Asymmetric algorithms

- `RS256`
- `RS384`
- `RS512`
- `ES256`
- `ES384`
- `ES512`
- `EdDSA`

### Key

Generators also require a key, which is specified using the `key` key.
If you're using a symmetrical algorithm, this should be a string, otherwise it should be an array of two strings, keyed
as `signing` and `verification`.
You can prefix the key with the following values to indicate the type of key:

- `base64:` - base64-encoded
- `file:` - file path`

#### Symmetrical algorithms

```php
'algo'   => \Ollieread\JWT\Algorithm::HS256,
'key'    => env('JWT_AUTH_KEY'),
```

#### Asymmetrical algorithms

```php
'algo'   => \Ollieread\JWT\Algorithm::RS256,
'key'    => [
    'signing'      => env('JWT_SIGNING_KEY'),
    'verification' => env('JWT_VERIFICATION_KEY'),
],
```

### Expiry

Generators can also have an expiry, which should either be an `int` representing the seconds until the token expires,
or a `string` representing either a [DateInterval](https://www.php.net/manual/en/dateinterval.construct.php) or a
[strtotime](https://www.php.net/manual/en/function.strtotime.php) string.
This value can also be `null` to indicate that the token should never expire.
If no expiry is specified, the default expiry will be used, which is `3600` seconds (1 hour).

```php
'expiry' => '2 hours'
```

### Claims

By default, the JWT claims `sub`, `iat` and `exp` will be set automatically, and cannot be overridden, but you can add
additional claims using implementations of the `\Ollieread\JWT\Contracts\JWTClaim` interface.
You can add additional claims by specifying a claim class in the `claims` key.

```php
'claims' => [
    \Ollieread\JWT\Claims\AppNameAsIssuer::class,
    \Ollieread\JWT\Claims\AppNameInAudience::class,
],
```

All claims are passed through the Laravel service container, so dependencies can be injected into them, but if you need
to pass parameters to the constructor, you can do so by specifying an array instead of a class name.
When doing this, the first item in the array should be the class name, and the rest should be parameters to pass to the
constructor.

```php
[\Ollieread\JWT\Claims\NotWithin::class, '1 hour']
```

This package also comes with a handful of default implementations, which you can use.

- `\Ollieread\JWT\Claims\AppNameAsIssuer`* - Sets the `iss` claim to the application name (`app.name` in `config/app.
php`).
- `\Ollieread\JWT\Claims\AppNameInAudience` - Adds the application name (`app.name` in `config/app.php`) to the `aud`
  claim.
- `\Ollieread\JWT\Claims\AppUrlAsIssuer`* - Sets the `iss` claim to the application URL (`app.url` in `config/app.php`).
- `\Ollieread\JWT\Claims\AppUrlInAudience` - Adds the application URL (`app.url` in `config/app.php`) to the `aud`
  claim.
- `\Ollieread\JWT\Claims\AsAudience`* - Sets the `aud` claim to the provided array of strings.
- `\Ollieread\JWT\Claims\AsIssuer`* - Sets the `iss` claim to the provided string.
- `\Ollieread\JWT\Claims\GeneratorNameAsIssuer`* - Sets the `iss` claim to the generator name (`users` in the example).
- `\Ollieread\JWT\Claims\GeneratorNameInAudience` - Adds the generator name (`users` in the example) to the `aud` claim.
- `\Ollieread\JWT\Claims\InAudience` - Adds the provided string to the `aud` claim.
- `\Ollieread\JWT\Claims\NotWithin`* - Sets the `nbf` claim to the issued at time plus a `string` interval.

> [!NOTE]
> Any above that are marked with `*` are destructive, meaning that they will override any existing claims of the same
> name.

## Usage

To generate a JWT, you can use the `\Ollieread\JWT\JWTManager` service class.
Once you have an instance of it, you can call the `get` method to retrieve a generator by its name.

```php
$generator = app(JWTManager::class)->get('users');
```

### Generating

To generate a JWT, you can call the `generate` method on the generator, passing the subject of the token, which can be
either a `string` or `int`, with the `int` values being cast to a `string`.

```php
$token = $generator->generate($user->getKey());
```

This method will return an instance of `\Lcobucci\JWT\UnencryptedToken` which will allow you to inspect the token and
its claims.
When you need to the return the token, or make use of it, call `toString` on it.

```php
$generator = app(JWTManager::class)->get('users');
$token     = $generator->generate($user->getKey());

return $token->toString();
```

### Parsing

This doesn't work yet.
