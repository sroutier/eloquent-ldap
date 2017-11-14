<?php

namespace Sroutier\EloquentLDAP\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Auth;

class EloquentLDAPServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../migrations/' => database_path('migrations')
        ], 'migrations');

        $this->publishes([
            __DIR__.'/../config/config.php' => config_path('eloquent-ldap.php'),
        ], 'config');

        // use the vendor configuration file as fallback
         $this->mergeConfigFrom(
             __DIR__.'/../config/config.php', 'eloquent-ldap'
         );
    }

    /**
     * Register any package services.
     *
     * @return void
     */
    public function register()
    {

        Auth::provider('eloquent-ldap', function ($app, array $config) {
            // Return an instance of Illuminate\Contracts\Auth\UserProvider...
            return new EloquentLDAPUserProvider($app);
        });

    }
}