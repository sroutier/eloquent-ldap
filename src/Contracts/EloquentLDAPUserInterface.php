<?php

namespace Sroutier\EloquentLDAP\Contracts;

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

}
