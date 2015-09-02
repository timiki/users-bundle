<?php

namespace Timiki\Bundle\UsersBundle\Security\Providers;

use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Timiki\Bundle\UsersBundle\Models\User;
use Timiki\Bundle\UsersBundle\Models\UserEntity;

/**
 * Client class
 */
class EntityProvider implements UserProviderInterface
{

    /**
     * @var Container
     */
    protected $container;

    /**
     * @var string|null
     */
    protected $entity;

    /**
     * Create new entity users providers
     * @param array $options
     * @param Container $container
     */
    public function __construct(array $options, Container $container)
    {
        if (array_key_exists('entity', $options)) {
            $this->entity = $options['entity'];
        }

        $this->container = $container;
    }

    /**
     * Get entity for storage users
     *
     * @return \Doctrine\ORM\EntityRepository|null
     */
    public function getRepository()
    {
        if ($this->entity) {
            return $this->container->get('doctrine.orm.entity_manager')->getRepository($this->entity);
        }

        return null;
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
        if ($repository = $this->getRepository()) {
            if ($entity = $repository->findOneBy(['username' => $username])) {
                if ($entity instanceof UserEntity) {
                    return new User($entity->toArray());
                }
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
