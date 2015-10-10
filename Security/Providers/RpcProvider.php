<?php

namespace Timiki\Bundle\UsersBundle\Security\Providers;

use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Timiki\Bundle\UsersBundle\Models\User;
use Timiki\RpcClientCommon\Client;

/**
 * Client class
 */
class RpcProvider implements UserProviderInterface
{

    /**
     * @var Container
     */
    protected $container;

    /**
     * @var Client
     */
    protected $client;

    /**
     * Create new rpc users providers
     *
     * @param array $options
     * @param Container $container
     */
    public function __construct(array $options, Container $container)
    {
        // Create RPC client

        if (array_key_exists('type', $options)) {
            $type = $options['type'];
        } else {
            $type = 'json';
        }

        if (array_key_exists('address', $options)) {
            $address = $options['address'];
        } else {
            $address = null;
        }

        if (array_key_exists('options', $options)) {
            $options = $options['options'];
        } else {
            $options = [];
        }

        $this->client    = new Client($address, $options, $type);
        $this->container = $container;
    }

    /**
     * Get rpx client
     *
     * @return Client|null
     */
    public function getClient()
    {
        return $this->client;
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
        if ($client = $this->getClient()) {
            $result = $client->call('UserByUsername', ['username' => $username]);
            if (!empty($result->getResult()->error)) {
                return new User($result->getResult()->result->data);
            } else {
                // Error call RPC
                throw new UnsupportedUserException();
            }
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
        return $this->loadUserByUsername($user->getUsername());
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
        return $class === 'Timiki\Bundle\UsersBundle\Models\User';
    }
}
