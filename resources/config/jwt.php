<?php

return [

    'generators' => [

        'users' => [
            'algo'   => \Ollieread\JWT\Algorithm::HS256,
            'key'    => env('JWT_AUTH_KEY'),
            'claims' => [
                \Ollieread\JWT\Claims\AppNameAsIssuer::class,
                // \Ollieread\JWT\Claims\AppUrlAsIssuer::class,
                // [\Ollieread\JWT\Claims\AsIssuer::class, 'users'],
                // \Ollieread\JWT\Claims\GeneratorNameAsIssuer::class,
                \Ollieread\JWT\Claims\AppNameInAudience::class,
                // [\Ollieread\JWT\Claims\InAudience::class, 'users'],
                // [\Ollieread\JWT\Claims\AsAudience::class, ['users']],
                // \Ollieread\JWT\Claims\GeneratorNameInAudience::class,
                [\Ollieread\JWT\Claims\NotWithin::class, '1 hour'],
            ],
        ],

    ],

];
