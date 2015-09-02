<?php

namespace Timiki\Bundle\UsersBundle\Models;

use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\Role\Role;
use DateTime;
use StdClass;

/**
 * Base user class
 */
class User extends StdClass implements AdvancedUserInterface
{
    /**
     * @var array
     */
    protected $data;

    /**
     * Create new user model
     *
     * @param array $data
     */
    public function __construct(array $data)
    {
        // Check need fields
        if (!array_key_exists('id', $data)) {
            $data['id'] = '0';
        }
        if (!array_key_exists('created_at', $data)) {
            $data['created_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!array_key_exists('expired_at', $data)) {
            $data['expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!array_key_exists('username', $data)) {
            $data['username'] = 'guest';
        }
        if (!array_key_exists('email', $data)) {
            $data['email'] = '';
        }
        if (!array_key_exists('password', $data)) {
            $data['password'] = '';
        }
        if (!array_key_exists('password_expired_at', $data)) {
            $data['password_expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!array_key_exists('salt', $data)) {
            $data['salt'] = null;
        }
        if (!array_key_exists('roles', $data)) {
            $data['roles'] = [];
        }
        if (!array_key_exists('groups', $data)) {
            $data['groups'] = [];
        }
        if (!array_key_exists('note', $data)) {
            $data['note'] = '';
        }
        if (!array_key_exists('locked', $data)) {
            $data['locked'] = 'N';
        }
        if (!array_key_exists('locked_msg', $data)) {
            $data['locked_msg'] = '';
        }
        if (!array_key_exists('enabled', $data)) {
            $data['enabled'] = 'Y';
        }
        if (!array_key_exists('last_login_at', $data)) {
            $data['last_login_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!array_key_exists('last_login_at', $data)) {
            $data['last_login_ip'] = '0.0.0.0';
        }
        // Check date format
        if (!$data['created_at'] instanceof DateTime) {
            $data['created_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!$data['expired_at'] instanceof DateTime) {
            $data['expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!$data['password_expired_at'] instanceof DateTime) {
            $data['password_expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }
        if (!$data['last_login_at'] instanceof DateTime) {
            $data['last_login_at'] = DateTime::createFromFormat('Y-m-d H:i:s', '0000-00-00 00:00:00');
        }

        $this->data = $data;
    }

    /**
     * @param string $name
     * @return null
     */
    public function __get($name)
    {
        if (array_key_exists($name, $this->data)) {
            return $this->data[$name];
        }

        return null;
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->data;
    }

    /**
     * Checks whether the user's account has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw an AccountExpiredException and prevent login.
     *
     * @return bool true if the user's account is non expired, false otherwise
     *
     * @see AccountExpiredException
     */
    public function isAccountNonExpired()
    {
        if ($this->expired_at->format('Y-m-d H:i:s') === '0000-00-00 00:00:00') {
            return true;
        }

        $dateNow = new DateTime();

        if ($dateNow->format('U') < $this->expired_at->format('U')) {
            return true;
        }

        return false;
    }

    /**
     * Checks whether the user is locked.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a LockedException and prevent login.
     *
     * @return bool true if the user is not locked, false otherwise
     *
     * @see LockedException
     */
    public function isAccountNonLocked()
    {
        return $this->locked === 'N';
    }

    /**
     * Checks whether the user's credentials (password) has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a CredentialsExpiredException and prevent login.
     *
     * @return bool true if the user's credentials are non expired, false otherwise
     *
     * @see CredentialsExpiredException
     */
    public function isCredentialsNonExpired()
    {
        if ($this->password_expired_at->format('Y-m-d H:i:s') === '0000-00-00 00:00:00') {
            return true;
        }

        $dateNow = new DateTime();

        if ($dateNow->format('U') < $this->password_expired_at->format('U')) {
            return true;
        }

        return false;
    }

    /**
     * Checks whether the user is enabled.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a DisabledException and prevent login.
     *
     * @return bool true if the user is enabled, false otherwise
     *
     * @see DisabledException
     */
    public function isEnabled()
    {
        return $this->enabled === 'N';
    }

    /**
     * Returns the roles granted to the user.
     *
     * <code>
     * public function getRoles()
     * {
     *     return array('ROLE_USER');
     * }
     * </code>
     *
     * Alternatively, the roles might be stored on a ``roles`` property,
     * and populated in any number of different ways when the user object
     * is created.
     *
     * @return Role[]|Array The user roles
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string The password
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string|null The salt
     */
    public function getSalt()
    {
        if (empty($this->salt)) {
            return null;
        }

        return $this->salt;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials()
    {
        $this->data['password'] = null;
        $this->data['salt']     = null;
    }
}
