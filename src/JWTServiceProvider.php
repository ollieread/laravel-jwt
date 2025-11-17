<?php
declare(strict_types=1);

namespace Ollieread\JWT;

use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->registerManager();
    }

    private function registerManager(): void
    {
        $this->app->singleton(JWTManager::class);
    }

    public function boot(): void
    {
        $this->publishConfig();
    }

    private function publishConfig(): void
    {
        $this->publishes([
            dirname(__DIR__) . '/resources/config/jwt.php' => config_path('jwt.php'),
        ], 'config');
    }
}
