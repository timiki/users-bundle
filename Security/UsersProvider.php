<?php

namespace Timiki\Bundle\UsersBundle\Security;

use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

/**
 * Client class
 */
class UsersProvider implements UserProviderInterface
{
    /**
     * @var UserProviderInterface|null
     */
    protected $provider;

    /**
     * Create new entity users providers
     * @param $provider
     * @param array $options
     * @param Container $container
     */
    public function __construct($provider, array $options, Container $container)
    {
        $providerClass = '\\Timiki\\Bundle\\UsersBundle\\Security\\Providers\\' . ucfirst(strtolower($provider)) .'Provider';

        if (class_exists($providerClass)) {
            $this->provider = new $providerClass($options, $container);
        }
    }

    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return UserInterface
     *
     * @see UsernameNotFoundException
     *
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByUsername($username)
    {
        if ($this->provider) {
            return $this->provider->loadUserByUsername($username);
        }
        throw new UsernameNotFoundException();
    }

    /**
     * Refreshes the user for the account interface.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @param UserInterface $user
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException if the account is not supported
     */
    public function refreshUser(UserInterface $user)
    {
        if ($this->provider) {
            return $this->provider->refreshUser($user);
        }

        throw new UnsupportedUserException();
    }

    /**
     * Whether this provider supports the given user class.
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass($class)
    {
        if ($this->provider) {
            return $this->provider->supportsClass($class);
        }

        return false;
    }
}
