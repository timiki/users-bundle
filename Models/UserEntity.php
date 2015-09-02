<?php

namespace Timiki\Bundle\UsersBundle\Models;

/**
 * Base entity for user entity class
 */
abstract class UserEntity
{
    /**
     * Get object array
     */
    abstract  public function toArray();
}
