<?php

namespace Timiki\Bundle\UsersBundle\Security\Providers;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use \Symfony\Component\HttpFoundation\Request;
use Timiki\Bundle\UsersBundle\Models\User;
use Timiki\RpcClientCommon\Client;
use DateTime;

/**
 * Client class
 */
class RpcProvider implements UserProviderInterface
{

	/**
	 * @var ContainerInterface
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
	 * @param ContainerInterface $container
	 */
	public function __construct(array $options, ContainerInterface $container)
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

		$headers        = array_key_exists('headers', $options) ? $options['headers'] : [];
		$cookies        = array_key_exists('cookies', $options) ? $options['cookies'] : [];
		$forwardHeaders = array_key_exists('forwardHeaders', $options) ? $options['forwardHeaders'] : [];
		$forwardCookies = array_key_exists('forwardCookies', $options) ? $options['forwardCookies'] : [];

		if ($forwardHeaders) {
			foreach ($forwardHeaders as $header) {
				$headers[$header] = Request::createFromGlobals()->headers->get($header);
				if (strtolower($header) == 'client-ip') {
					$headers[$header] = [Request::createFromGlobals()->getClientIp()];
				}
			}
		}

		if ($forwardCookies) {
			foreach ($forwardCookies as $name => $values) {
				if (in_array($name, $forwardCookies)) {
					$cookies[$name] = $values;
				}
			}
		}

		$this->client = new Client($address, $type, $headers, $cookies);
		$this->setContainer($container);
	}

	/**
	 * Set container
	 *
	 * @param ContainerInterface|null $container
	 * @return $this
	 */
	public function setContainer(ContainerInterface $container)
	{
		if ($container instanceof ContainerInterface) {
			$this->container = $container;
		}

		return $this;
	}

	/**
	 * Get container
	 *
	 * @return ContainerInterface|null
	 */
	public function getContainer()
	{
		return $this->container;
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

			// Before run call need stop session
			if ($this->getContainer() !== null) {
				$this->getContainer()->get('session')->save();
			}

			$result = $client->call('UserByUsername', ['username' => $username]);

			// After run call need restart session
			if ($this->getContainer() !== null) {
				$this->getContainer()->get('session')->migrate();
			}

			if (empty($result->getResult()->error)) {
				// Get data from rpc response
				$data = (array)$result->getResult()->result->data;
				// Ro DateTime
				if (array_key_exists('created_at', $data)) {
					$data['created_at'] = DateTime::createFromFormat('Y-m-d H:i:s', $data['created_at']);
				}
				if (array_key_exists('expired_at', $data)) {
					$data['expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', $data['expired_at']);
				}
				if (array_key_exists('password_expired_at', $data)) {
					$data['password_expired_at'] = DateTime::createFromFormat('Y-m-d H:i:s', $data['password_expired_at']);
				}
				if (array_key_exists('last_login_at', $data)) {
					$data['last_login_at'] = DateTime::createFromFormat('Y-m-d H:i:s', $data['last_login_at']);
				}

				return new User($data);
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
