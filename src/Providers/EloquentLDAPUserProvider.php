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
     * Shortcut to the config section.
     *
     * @var Array
     */

    protected $ldapConfig;

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
        $this->ldapConfig = $this->app['config']['eloquent-ldap'];
        $this->user_model = $this->app['config']['auth.model'];
        $this->group_model = $this->ldapConfig['group_model'];
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
             $this->ldapConfig['enabled'] &&
             $this->ldapConfig['create_accounts']
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
                ( isset($user->auth_type) && ($this->ldapConfig['label_internal'] === $user->auth_type) ) ||
                ( !isset($user->auth_type) )
             )
           ) {
            $plain = $credentials['password'];
            $credentialsValidated = $this->hasher->check($plain, $user->getAuthPassword());
        } else if ( ($this->ldapConfig['enabled']) && ($this->ldapConfig['label_ldap'] === $user->auth_type) ) {
            // Validate credentials against LDAP/AD server.
            $credentialsValidated = $this->validateLDAPCredentials($credentials);
            // If validated and config set to resync group membership on login.
            if ( $credentialsValidated && ($this->ldapConfig['resync_on_login']) ) {
                // First, revoke membership to all groups marked to 'resync_on_login'.
                $this->revokeMembership($user);
                // Then replicate group membership.
                $this->replicateMembershipFromLDAP($user);
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

    /**
     * Creates a local user from the information gained from the LDAP/AD
     * server.
     *
     * @param $userName The name of the user to create.
     */
    private function createUserFromLDAP($userName)
    {
        $user = null;

        $ldapUserInfo = $this->getLDAPUserInfo($userName);
        // If we found the user in LDAP
        if (true == $ldapUserInfo ) {
            $firstName = $this->GetArrayIndexedValueOrDefault($ldapUserInfo, $this->ldapConfig['first_name_field'], 0, $userName);
            $lastName  = $this->GetArrayIndexedValueOrDefault($ldapUserInfo, $this->ldapConfig['last_name_field'], 0, '');
            $email     = $this->GetArrayIndexedValueOrDefault($ldapUserInfo, $this->ldapConfig['email_field'], 0, '');
            $enabled   = (($ldapUserInfo['useraccountcontrol'][0] & 2) == 0);

            $userModel = $this->createUserModel();

            $ldapFields = [ 'first_name'    => $firstName,
                            'last_name'     => $lastName,
                            'email'         => $email,
                            'enabled'       => $enabled,
                          ];

            $validator = Validator::make($ldapFields, $userModel::getCreateValidationRules());

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
                    'password'   => 'Laravel Rock! ASP.Net blows! ' . date("Y-m-d H:i:s"),
                    'auth_type'  => $this->ldapConfig['label_ldap'],
                ));

                if ($enabled) {
                    $user->enabled = true;
                } else {
                    $user->enabled = false;
                }
                $user->save();

                if ($this->ldapConfig['replicate_group_membership']) {
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
                "account_suffix"     => $this->ldapConfig['account_suffix'],
                "base_dn"            => $this->ldapConfig['base_dn'],
                "domain_controllers" => $this->ldapConfig['server'],
                "admin_username"     => $this->ldapConfig['user_name'],
                "admin_password"     => $this->ldapConfig['password'],
                "real_primarygroup"  => $this->ldapConfig['return_real_primary_group'],
                "recursive_groups"   => $this->ldapConfig['recursive_groups'],
                "sso"                => false, // $ldapConfig['sso'], // NOT SUPPORTED HARD CODED TO FALSE.
                "follow_referrals"   => false, // $ldapConfig['follow_referrals'], // NOT SUPPORTED HARD CODED TO FALSE.
            ];
            // Create the communication option part, add the encryption and port info.
            if ('tls' === $this->ldapConfig['secured']) {
                $comOpt = [
                    "use_ssl" => false,
                    "use_tls" => true,
                    "ad_port" => $this->ldapConfig['secured_port'], // TODO: Should this be secured_port or port?!?!
                ];
            } else if ('ssl' === $this->ldapConfig['secured']) {
                $comOpt = [
                    "use_ssl" => true,
                    "use_tls" => false,
                    "ad_port" => $this->ldapConfig['secured_port'],
                ];
            } else {
                $comOpt = [
                    "use_ssl" => false,
                    "use_tls" => false,
                    "ad_port" => $this->ldapConfig['port'],
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
     * Queries the LDAP/AD server for information on the user.
     *
     * @param  $userName    The name of the user to get information for.
     * @return Adldap User  The user information.
     */
    private function getLDAPUserInfo($username)
    {
        $adldap = false;
        $adResults = false;

        try {
            $ldapQuery = $this->ldapConfig['user_filter'];
            if (strpos($ldapQuery, self::USER_TOKEN)) {
                $ldapQuery = str_replace(self::USER_TOKEN, $username, $ldapQuery);
            }
            else {
                throw new \Exception("Invalid AD/LDAP query filter, check the configuration of 'LDAP_USER_FILTER'.");
            }

            $ldapFields = [
                $this->ldapConfig['first_name_field'],
                $this->ldapConfig['last_name_field'],
                $this->ldapConfig['email_field'],
                'useraccountcontrol',
            ];

            // Build connection info.
            $ldapConOp = $this->GetLDAPConnectionOptions();

//            // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
//            ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);

            // Connect to AD/LDAP
            $adldap = new Adldap($ldapConOp);

            $adResults = $adldap->search()->select($ldapFields)->query($ldapQuery);

            if (isset($adResults) && is_array($adResults) && isset($adResults[0])) {
                $adResults = $adResults[0];
            }

            if (!$adResults) {
                $this->handleLDAPError($adldap);
            }
        } catch (\Exception $ex) {
            Log::error('Exception retrieving user information: ' . $ex->getMessage());
            Log::error($ex->getTraceAsString());
        }

        // Close connection.
        if (isset($adldap)) {
            unset($adldap);
        }

        return $adResults;
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
            $groupModel = $this->createGroupModel();
            $ldapConOp = $this->GetLDAPConnectionOptions();

//            // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
//            ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);

            // Connect to AD/LDAP
            $adldap = new Adldap($ldapConOp);
            // Request the user's group membership.
            $adldapGroups = $adldap->users()->find($user->username)->getGroups();

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

    //            // Set LDAP debug log level - useful in DEV, dangerous in PROD!!
    //            ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7);

            // Try to authenticate using AD/LDAP
            $adldap = new Adldap($ldapConOp);
            $authUser = $adldap->authenticate($userName, $userPassword);
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