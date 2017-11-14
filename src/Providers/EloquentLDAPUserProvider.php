<?php

namespace Sroutier\EloquentLDAP\Providers;

use Illuminate\Support\Str;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
use Illuminate\Contracts\Foundation\Application;
use Adldap\Adldap;
use Illuminate\Support\Facades\Log;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Monolog\Logger;
use Settings;
use Validator;

class EloquentLDAPUserProvider implements UserProvider
{
    /**
     * The replacement token used to identify the username to search for.
     */
    const USER_TOKEN = '%username';

    /**
     * The application instance.
     *
     * @var \Illuminate\Contracts\Foundation\Application
     */
    protected $app;

    /**
     * The hasher implementation.
     *
     * @var \Illuminate\Contracts\Hashing\Hasher
     */
    protected $hasher;

    /**
     * The Eloquent user model.
     *
     * @var string
     */
    protected $user_model;

    /**
     * The Eloquent group model.
     *
     * @var string
     */
    protected $group_model;

    /**
     * The connection options for LDAP.
     *
     * @var Array
     */

    protected $ldapConOp;

    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->hasher = $this->app['hash'];
        $this->user_model = $this->getUserModel();
        $this->group_model = Settings::get('eloquent-ldap.group_model');
    }

    public function getUserModel()
    {
        return $this->app['config']['auth.providers.users.model'];
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        return $this->createUserModel()->newQuery()->find($identifier);
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $userModel = $this->createUserModel();

        return $userModel->newQuery()
            ->where($userModel->getKeyName(), $identifier)
            ->where($userModel->getRememberTokenName(), $token)
            ->first();
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);

        $user->save();
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.
        $query = $this->createUserModel()->newQuery();

        foreach ($credentials as $key => $value) {
            if (!Str::contains($key, 'password')) {
                $query->where($key, $value);
            }
        }

//        return $query->first();

        $user = $query->first();

        // If the user was not found in the local database, and LDAP authentication
        // is enabled, and the option is set to automatically create new accounts
        // on first login, create the user and return it. Otherwise return what
        // we found, which could be a user or null.
        if (
             is_null($user) &&
             Settings::get('eloquent-ldap.enabled') &&
             Settings::get('eloquent-ldap.create_accounts')
           ) {
            $user = $this->createUserFromLDAP($credentials['username']);
        }

        return $user;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(UserContract $user, array $credentials)
    {
        $credentialsValidated = false;

        // If the user is set AND, either of auth_type 'internal' or with
        // auth_type unset or null, then validate against the stored
        // password hash. Otherwise if the LDAP authentication
        // method is enabled, try it.
        if ( isset($user) &&
             (
                ( isset($user->auth_type) && (Settings::get('eloquent-ldap.label_internal') === $user->auth_type) ) ||
                ( !isset($user->auth_type) )
             )
           ) {
            $plain = $credentials['password'];
            $credentialsValidated = $this->hasher->check($plain, $user->getAuthPassword());
        } else if ( (Settings::get('eloquent-ldap.enabled')) && (Settings::get('eloquent-ldap.label_ldap') === $user->auth_type) ) {
            // Validate credentials against LDAP/AD server.
            $credentialsValidated = $this->validateLDAPCredentials($credentials);
            // If validated and config set to resync group membership on login.
            if ( $credentialsValidated ) {
                // Sync user enable/disable state
                $this->syncEnable($user);
                if ( (Settings::get('eloquent-ldap.resync_on_login')) && (Settings::get('eloquent-ldap.replicate_group_membership'))) {
                    // First, revoke membership to all groups marked to 'resync_on_login'.
                    $this->revokeMembership($user);
                    // Then replicate group membership.
                    $this->replicateMembershipFromLDAP($user);
                }
            }
         }

        return $credentialsValidated;
    }

    /**
     * Returns class name of the user model.
     *
     * @return string
     */
    public function userModelClassName()
    {
        $class = '\\'.ltrim($this->user_model, '\\');

        return $class;
    }

    /**
     * Create a new instance of the user model.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function createUserModel()
    {
        $class = $this->userModelClassName();

        return new $class;
    }

    /**
     * Create a new instance of the group model.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function createGroupModel()
    {
        $class = '\\'.ltrim($this->group_model, '\\');

        return new $class;
    }


    private function syncEnable($user)
    {
        $ldapUser = $this->getLDAPUser($user->username);
        // If we found the user in LDAP
        if (true == $ldapUser ) {
            $enabled = (($ldapUser->getFirstAttribute('useraccountcontrol') & 2) == 0);

            if ($enabled) {
                $user->enabled = true;
            }
            else {
                $user->enabled = false;
            }
            $user->save();
        }
    }


    /**
     * Creates a local user from the information gained from the LDAP/AD
     * server.
     *
     * @param $userName The name of the user to create.
     */
    private function createUserFromLDAP($userName)
    {
        $user = null;

        $ldapUser = $this->getLDAPUser($userName);
        // If we found the user in LDAP
        if (true == $ldapUser ) {
            $firstName = $ldapUser->getFirstAttribute(Settings::get('eloquent-ldap.first_name_field'));
            $lastName  = $ldapUser->getFirstAttribute(Settings::get('eloquent-ldap.last_name_field'));
            $email     = $ldapUser->getFirstAttribute(Settings::get('eloquent-ldap.email_field'));
            $enabled   = (($ldapUser->getFirstAttribute('useraccountcontrol') & 2) == 0);

            $userModel = $this->createUserModel();

            $ldapFields = [ 'username'      => $userName,
                            'first_name'    => $firstName,
                            'last_name'     => $lastName,
                            'email'         => $email,
                            'enabled'       => $enabled,
                          ];

            $validator = Validator::make($ldapFields, $userModel::getCreateValidationRules($this->app));

            if ($validator->fails()) {
                Log::error('Validation failed for user ['.$userName.'], in [EloquentLDAPUserProvider::createUserFromLDAP].');
                $messages = $validator->errors();
                foreach ($messages->all() as $message) {
                    Log::error('Validation message: ' . $message);
                }

            }
            else {
                $user = $userModel->create(array(
                    'username'   => $userName,
                    'first_name' => $firstName,
                    'last_name'  => $lastName,
                    'email'      => $email,
                    'password'   => 'Password handled by AD/LDAP.',
                    'auth_type'  => Settings::get('eloquent-ldap.label_ldap'),
                ));

                if ($enabled) {
                    $user->enabled = true;
                } else {
                    $user->enabled = false;
                }
                $user->save();

                if (Settings::get('eloquent-ldap.replicate_group_membership')) {
                    $this->replicateMembershipFromLDAP($user);
                }
            }

        }

        return $user;
    }

    /**
     * Builds the LDAP connection options from the configuration files.
     *
     * @return array
     */
    private function GetLDAPConnectionOptions()
    {

        if (!isset($this->ldapConOp) || is_null($this->ldapConOp)) {
            // Build basic LDAP connection configuration.
            $this->ldapConOp = [
                "account_suffix"     => Settings::get('eloquent-ldap.account_suffix'),
                "base_dn"            => Settings::get('eloquent-ldap.base_dn'),
                "domain_controllers" => [ Settings::get('eloquent-ldap.server') ], // config item must be an array.
                "admin_username"     => Settings::get('eloquent-ldap.user_name'),
                "admin_password"     => Settings::get('eloquent-ldap.password'),
//                "real_primarygroup"  => Settings::get('eloquent-ldap.return_real_primary_group'),
//                "recursive_groups"   => Settings::get('eloquent-ldap.recursive_groups'),
//                "sso"                => false, // Settings::get('eloquent-ldap.sso'), // NOT SUPPORTED HARD CODED TO FALSE.
                "follow_referrals"   => false, // Settings::get('eloquent-ldap.follow_referrals'), // NOT SUPPORTED HARD CODED TO FALSE.
            ];
            // Create the communication option part, add the encryption and port info.
            if ('tls' === Settings::get('eloquent-ldap.secured')) {
                $comOpt = [
                    "use_ssl" => false,
                    "use_tls" => true,
                    "port" => Settings::get('eloquent-ldap.secured_port'),
                ];
            } else if ('ssl' === Settings::get('eloquent-ldap.secured')) {
                $comOpt = [
                    "use_ssl" => true,
                    "use_tls" => false,
                    "port" => Settings::get('eloquent-ldap.secured_port'),
                ];
            } else {
                $comOpt = [
                    "use_ssl" => false,
                    "use_tls" => false,
                    "port" => Settings::get('eloquent-ldap.port'),
                ];
            }
            // Merge all options together.
            $this->ldapConOp = array_merge($this->ldapConOp, $comOpt);
        }

        return $this->ldapConOp;

    }

    /**
     * Returns the value of a key in an array, or if not found, returns the
     * default provided.
     *
     * @param $array         The array to return the value from.
     * @param $key           The key to lookup.
     * @param null $default  The default value to return if the key does not exist.
     * @return               The value requested or the default provided.
     */
    private function GetArrayValueOrDefault($array, $key, $default = null) {
        $value = $default;

        try {
            $value = $array[$key];
            if (null === $value) {
                $value = $default;
            }
        }
        catch( Exception $ex) {
            $value = $default;
        }

        return $value;
    }

    /**
     * Returns the value of a key at an index in a multi-dimensional array, or
     * if not found, returns the default provided.
     *
     * @param $array         The array to return the value from.
     * @param $key           The key to lookup.
     * @param $index         The index of the value to return.
     * @param null $default  The default value to return if the key does not exist.
     * @return               The value requested or the default provided.
     */
    private function GetArrayIndexedValueOrDefault($array, $key, $index, $default = null) {
        $value = $default;

        try {
            $value = $this->GetArrayValueOrDefault($array, $key, $default);
            if ( (isset($value)) && ($value !== $default) ) {
                $value = $value[$index];
            }
        }
        catch( Exception $ex) {
            $value = $default;
        }

        return $value;
    }

    /**
     * Queries the LDAP/AD server for a user.
     *
     * @param  $userName    The name of the user to get information for.
     * @return Adldap User  The user.
     */
    private function getLDAPUser($username)
    {
        $adldap = false;
        $adUser = false;

        try {
            $ldapQuery = Settings::get('eloquent-ldap.user_filter');
            if (strpos($ldapQuery, self::USER_TOKEN)) {
                $ldapQuery = str_replace(self::USER_TOKEN, $username, $ldapQuery);
            }
            else {
                throw new \Exception("Invalid AD/LDAP query filter, check the configuration of 'LDAP_USER_FILTER'.");
            }

            $ldapFields = [
                Settings::get('eloquent-ldap.username_field'),
                Settings::get('eloquent-ldap.first_name_field'),
                Settings::get('eloquent-ldap.last_name_field'),
                Settings::get('eloquent-ldap.email_field'),
                'useraccountcontrol',
                'dn',
            ];

            // Build connection info.
            $ldapConOp = $this->GetLDAPConnectionOptions();

            if (Settings::get('eloquent-ldap.debug')) {
                // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
                ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
            }

            // Connect to AD/LDAP
            $adldap = new Adldap();
            $adldap->addProvider($ldapConOp);
            $provider = $adldap->connect();

            // Search...
            $adUser = $provider->search()->select($ldapFields)->rawFilter($ldapQuery)->first();
//            $adResults = $provider->search()->select($ldapFields)->rawFilter($ldapQuery)->get();
//
//            if (isset($adResults) && is_array($adResults) && isset($adResults[0])) {
//                $adResults = $adResults[0];
//            }

            if (!$adUser) {
                $this->handleLDAPError($adldap);
            }
        } catch (\Exception $ex) {
            Log::error('Exception retrieving user information: ' . $ex->getMessage());
            Log::error($ex->getTraceAsString());
        }

        // Close connection.
        if (isset($provider)) {
            unset($provider);
        }
        // Close connection.
        if (isset($adldap)) {
            unset($adldap);
        }

        return $adUser;
    }

    /**
     * Revoke membership to all local group that are marked with
     * 'resync_on_login' as 1 or true.
     *
     * @param $user The user to revoke group membership from.
     */
    private function revokeMembership($user)
    {
        try {

            foreach($user->membershipList as $group) {
                if ($group->resync_on_login) {
                    $user->membershipList()->detach($group);
                }
            }

        } catch (\Exception $ex) {
            Log::error('Exception revoking local group membership for user: ' . $user->username . ', Exception message: ' . $ex->getMessage());
            Log::error($ex->getTraceAsString());
        }

    }

    /**
     * Grants membership to local groups for each LDAP/AD group that the user
     * is a member of. See the option "LDAP_RECURSIVE_GROUPS" to enable
     * deep LDAP/AD group probe.
     * NOTE: This will not maintain the hierarchical structure of the groups,
     * instead the structure will be 'flattened'. If you want to maintain
     * the hierarchical structure, set the option "LDAP_RECURSIVE_GROUPS"
     * to false, and build a group structure that mirrors the LDAP/AD
     * structure.
     *
     * @param  $user      The user to replicate group membership for.
     * @throws Exception
     */
    private function replicateMembershipFromLDAP($user)
    {
        $adldap = false;

        try {
            $username = $user->username;
            $groupModel = $this->createGroupModel();
            $ldapConOp = $this->GetLDAPConnectionOptions();
            $ldapRecursive = Settings::get('eloquent-ldap.recursive_groups');

            if (Settings::get('eloquent-ldap.debug')) {
                // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
                ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
            }

            // Connect to AD/LDAP
            $adldap = new Adldap();
            $adldap->addProvider($ldapConOp);
            $provider = $adldap->connect();

            // Locate the user
            $adldapUser = $provider->search()->users()->find($username);
            // Request the user's group membership.
            $adldapGroups = $adldapUser->getGroups([], true);

            foreach($adldapGroups as $adldapGroup) {
                try {
                    $adldapGroupName = $adldapGroup->getName();
                    $localGroup = null;
                    $localGroup = $groupModel->where('name', $adldapGroupName)->firstOrFail();
                    if ( !$user->isMemberOf($adldapGroupName) ) {
                        $user->membershipList()->attach($localGroup->id);
                    }
                } catch (ModelNotFoundException $e) {
                    // Mute the exception as we expect not to find all groups.
                }
            }

        } catch (\Exception $ex) {
            Log::error('Exception replicating group membership for user: ' . $user->username . ', Exception message: ' . $ex->getMessage());
            Log::error($ex->getTraceAsString());
            $this->handleLDAPError($adldap);
        }

        // Close connection.
        if (isset($provider)) {
            unset($provider);
        }
        // Close connection.
        if (isset($adldap)) {
            unset($adldap);
        }

    }

    /**
     * Validates the credentials against the configured LDAP/AD server.
     * The credentials are passed in an array with the keys 'username'
     * and 'password'.
     *
     * @param  array   $credentials   The credentials to validate.
     * @return boolean
     */
    private function validateLDAPCredentials(array $credentials)
    {
        $credentialsValidated = false;
        $adldap = false;

        try {

            $userPassword = $credentials['password'];
            $userName     = $credentials['username'];
            $ldapConOp    = $this->GetLDAPConnectionOptions();

            if (Settings::get('eloquent-ldap.debug')) {
                // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
                ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);
            }

            // Try to authenticate using AD/LDAP
            // Connect to AD/LDAP
            $adldap = new Adldap();
            $adldap->addProvider($ldapConOp);
            $provider = $adldap->connect();

            // For LDAP servers, the authentication is done with the full DN,
            // Not the username with the suffix as is done for MSAD servers.
            if ('LDAP' === Settings::get('eloquent-ldap.server_type')) {
                $ldapUser = $this->getLDAPUser($userName);
                $userName = $this->GetArrayValueOrDefault($ldapUser, 'dn', '');
            }

            $authUser = $provider->auth()->attempt($userName, $userPassword);
            // If the user got authenticated
            if ($authUser == true) {
                $credentialsValidated = true;
            } else {
                $this->handleLDAPError($adldap);
                $credentialsValidated = false;
            }
        } catch (\Exception $ex) {
            Log::error('Exception validating LDAP credential for user: ' . $userName . ', Exception message: ' . $ex->getMessage());
            Log::error($ex->getTraceAsString());
            $this->handleLDAPError($adldap);
            $credentialsValidated = false;
        }

        // Close connection.
        if (isset($provider)) {
            unset($provider);
        }
        // Close connection.
        if (isset($adldap)) {
            unset($adldap);
        }

        return $credentialsValidated;
    }

    /**
     * Logs the last LDAP error if it is not "Success".
     *
     * @param array $adldap   The instance of the adLDAP object to check for
     *                        error.
     */
    private function handleLDAPError(\Adldap\Adldap $adldap)
    {
        if (false != $adldap) {
            // May be helpful for finding out what and why went wrong.
            $adLDAPError = $adldap->getConnection()->getLastError();
            if ("Success" != $adLDAPError) {
                Log::error('Problem with LDAP:' . $adLDAPError);
            }
        }
    }
}
