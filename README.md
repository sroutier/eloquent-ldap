# eloquent-ldap

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)

A Laravel package that first tries to log the user against the internal 
database, if that fails, it tries against the configured LDAP/AD 
server. Optionally it will create a local user record on first
login of an LDAP user, as well as grant that user permissions
to local groups that have matching names of the LDAP groups
that the user is a member of.


## Install

Via Composer

``` bash
$ composer require sroutier/eloquent-ldap
```

## Publish assets

To publish the assets, config file and migration scripts, run this command:

``` bash
$ php artisan vendor:publish --provider="Sroutier\EloquentLDAP\Providers\EloquentLDAPServiceProvider"
```

This will publish a config file and a migration file.

## Migration

The migration script will add a new column 'auth_type' to the schema of the 
'users' table, and one column 'resync_on_login' to the 'groups' table. You 
should already have both tables, but if you do not or if you want to use
different tables for those purposes, the migration to create those 
tables is provided as an example, but commented out. You will 
want to review the migration script and adjust according to 
your scenario.

Once ready, run the migration script with this command:

``` bash
$ php artisan migrate
```

## Configure

The recommended way to configure this package is by defining the following 
variables in you '.env' file and adjusting the values there. For a 
detailed explanation of each setting, refer to the config file 
that you published above.
```
LDAP_ENABLED=false
LDAP_CREATE_ACCOUNTS=true
LDAP_REPLICATE_GROUP_MEMBERSHIP=true
LDAP_RESYNC_ON_LOGIN=true
LDAP_GROUP_MODEL=App\Models\Group
LDAP_LABEL_INTERNAL=internal
LDAP_LABEL_LDAP=ldap
LDAP_ACCOUNT_SUFFIX=@company.com
LDAP_BASE_DN=DC=department,DC=company,DC=com
LDAP_SERVER=ldapsrv01.company.com
LDAP_PORT=389
LDAP_USER_NAME=ldap_reader
LDAP_PASSWORD=PaSsWoRd
LDAP_RETURN_REAL_PRIMARY_GROUP=true
LDAP_SECURED=false
LDAP_SECURED_PORT=636
LDAP_RECURSIVE_GROUPS=true
LDAP_SSO=false
LDAP_USERNAME_FIELD=samaccountname
LDAP_EMAIL_FIELD=userprincipalname
LDAP_FIRST_NAME_FIELD=givenname
LDAP_LAST_NAME_FIELD=sn
```

## Usage

The 'users' table/model must have the following columns/attributes named 
'username', 'first_name', 'last_name' and 'email'. The migration 
script provided with this package has an example of how to 
create such a table but it is commented out. 

Also your login view and 'AuthController' must accept a user name and password.
They can accept other fields if you want, such as email, security token, 
etc... But the first time a new user tries to log in, since he will not
be found in the local database, the package will need the user name to
authenticate against the LDAP server. 

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email sroutier@gmail.com instead of using the issue tracker.

## Credits

- [Sebastien Routier](https://github.com/sroutier)
- [All Contributors](https://github.com/sroutier/eloquent-ldap/graphs/contributors)

## License

The GNU General Public License Version 3 (GPLv3). Please see [License File](LICENSE.md) for more information.

[ico-version]: https://img.shields.io/packagist/v/sroutier/eloquent-ldap.svg
[ico-license]: https://img.shields.io/badge/licence-GPLv3-brightgreen.svg

[link-packagist]: https://packagist.org/packages/sroutier/eloquent-ldap
[link-author]: https://github.com/sroutier
