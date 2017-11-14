<?php

namespace Sroutier\EloquentLDAP\Contracts;

use Illuminate\Container\Container as Application;

interface EloquentLDAPUserInterface
{
    /**
     * Checks if the user is a member of the group.
     *
     * @param $name The name of the group to check the membership of.
     * @return bool
     */
    public function isMemberOf($name);

    /**
     * Alias to the BelongsToMany relationship between your user model and
     * your group model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function membershipList();


    /**
     * Returns the validation rules required to create a User.
     *
     * @return array
     */
    public static function getCreateValidationRules(Application $app);

    /**
     * Returns the validation rules required to update a User.
     *
     * @return array
     */
    public static function getUpdateValidationRules(Application $app, $id);
}
