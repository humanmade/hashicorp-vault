<?php
/**
 * HashiCorp Vault integration for WordPress.
 *
 * Access Vault secrets, utilising WordPress APIs for maximum scalability.
 */

declare( strict_types = 1 );

namespace HM\Hashicorp_Vault;

use Exception, RuntimeException;
use Vault;
use Vault\AuthenticationStrategies;
use VaultTransports;

/**
 * Set up plugin.
 *
 * Register actions and filters.
 */
function set_up() : void {
	add_action( 'humanmade/hashicorp-vault/update_secret', __NAMESPACE__ . '\update_secret', 10, 1 );
}

/**
 * Get a Vault secret (cached).
 *
 * @param string $secret Secret name.
 *
 * @return array|null Returns null if unable to be retrieve the secret for an uncaught reason.
 */
function get_secret( string $secret ) : ?array {
	$transient = get_transient_name( $secret );
	$data      = get_transient( $transient );

	if ( $data === false ) {
		try {
			$data = get_secret_from_vault( $secret );
		} catch ( Exception $error ) {
			return null;
		}

		set_transient( $transient, $data, 0 );

		// Random reduces likelihood that many keys will start expiring at the same time.
		$timestamp = time() + round( ( $data['lease_duration'] / 4 ) * 3 ) + mt_rand( 0, 30 );

		// Auto-update before lease expiry.
		wp_schedule_single_event(
			$timestamp,
			'humanmade/hashicorp-vault/update_secret',
			[ $secret ]
		);
	}

	return $data;
}

/**
 * Get a secret directly from Vault (not cached).
 *
 * @param string $secret Secret name.
 *
 * @return array {
 *     Secret data from Vault. In addition to a secret's key/value pairs, the response also includes:
 *
 *     @type int    $lease_duration Remaining duration of the lease, in seconds.
 *     @type string $lease_id       ID of this lease.
 *
 *     If Vault has its AWS Secrets Engine enabled, these items will also be returned for AWS secrets:
 *
 *     @type string $access_key     AWS access key.
 *     @type string $secret_key     AWS secret key.
 *     @type string $security_token AWS temporary session token.
 * }
 *
 * @throws \InvalidArgumentException
 * @throws RuntimeException
 * @throws \Vault\Exceptions\ClientException
 * @throws \Vault\Exceptions\TransportException
 * @throws \Vault\Exceptions\ServerException
 */
function get_secret_from_vault( string $secret ) : array {
	$vault = new Vault\Client(
		new VaultTransports\Guzzle6Transport( [
			'base_uri' => get_vault_url(),
		] )
	);

	$authenticated = $vault
		->setAuthenticationStrategy( new AuthenticationStrategies\TokenAuthenticationStrategy( get_auth_token() ) )
		->authenticate();

	if ( $authenticated === false ) {
		throw new RuntimeException( 'Unable to authenticate.' );
	}

	$response = $vault->read( $secret );

	return array_merge(
		$response->getData(),
		[
			'lease_duration' => (int) $response->leaseDuration,
			'lease_id'       => $response->leaseId,
		]
	);
}

/**
 * Update a secret's cached value before its lease expires.
 *
 * Currently, to renew the lease, we fetch the entire secret again to get a new lease.
 * A future enhancement would be to check if the secret supports `lease_renewable` and,
 * if so, use that to renew the existing lease programatically via Vault's APIs.
 *
 * @param string $secret Secret name.
 */
function update_secret( string $secret ) : void {
	$lock_name = 'humanmade/hashicorp-vault/update_secret';

	if ( ! wpdesk_acquire_lock( $lock_name ) ) {
		return;
	}

	try {
		$data = get_secret_from_vault( $secret );
	} catch ( Exception $error ) {
		wpdesk_release_lock( $lock_name );
		return;
	}

	set_transient( get_transient_name( $secret ), $data, 0 );
	wpdesk_release_lock( $lock_name );
}

/**
 * Get a transient name from a Vault secret.
 *
 * Consolidates naming conventions and key length management.
 *
 * @param string $secret Vault secret to use as the base of a transient.
 *
 * @return string
 */
function get_transient_name( string $transient ) : string {
	return 'hm-hashicorp-vault-' . md5( $transient );
}

/**
 * Get the URL to the Vault service.
 *
 * @return string
 */
function get_vault_url() : string {
	$url = defined( 'HM_HASHICORP_VAULT_URL' ) ? HM_HASHICORP_VAULT_URL : '';

	/**
	 * Filter the URL to the Vault service.
	 *
	 * @param string $url Value of HM_HASHICORP_VAULT_URL.
	 */
	return apply_filters(
		'humanmade/hashicorp-vault/get_vault_url',
		$url
	);
}

/**
 * Get the Vault authentication token.
 *
 * @return string
 */
function get_auth_token() : string {
	$token = defined( 'HM_HASHICORP_VAULT_AUTH_TOKEN' ) ? HM_HASHICORP_VAULT_AUTH_TOKEN : '';

	/**
	 * Filter the Vault authentication token.
	 *
	 * @param string $token Value of HM_HASHICORP_VAULT_URL.
	 */
	return apply_filters(
		'humanmade/hashicorp-vault/get_auth_token',
		$token
	);
}
