<?php
/**
 * HashiCorp Vault integration for WordPress.
 *
 * Access Vault secrets, utilising WordPress APIs for maximum scalability.
 *
 * @package HM\Hashicorp_Vault
 */

declare( strict_types = 1 );

namespace HM\Hashicorp_Vault;

use Exception;
use Psr\Log;
use RuntimeException;
use Vault;
use VaultTransports;
use Vault\AuthenticationStrategies;
use WPDesk\Mutex;

/**
 * WordPress cron task name for refreshing secrets.
 *
 * @var string
 */
const CRON_OPTION = 'humanmade/hashicorp-vault/update_secret';

/**
 * Set up plugin.
 *
 * Register actions and filters.
 */
function set_up() : void {
	add_action( CRON_OPTION, __NAMESPACE__ . '\update_secret', 10, 1 );
}

/**
 * Get a Vault secret (cached).
 *
 * @param string              $secret Secret name.
 * @param Log\LoggerInterface $logger Optional. A PSR-3 compatible logger to use for errors.
 *
 * @return array Secret data from Vault. See `get_secret_from_vault()`.
 */
function get_secret( string $secret, Log\LoggerInterface $logger = null ) : array {
	$transient = get_transient_name( $secret );
	$data      = get_transient( $transient );

	if ( $data === false ) {
		// If we don't have the secret, fetch it synchronously.
		$data = get_secret_from_vault( $secret, $logger );

		set_transient( $transient, $data, $data['lease_duration'] - 10 );
		schedule_next_secret_update( $secret, $data );
	}

	return $data;
}

/**
 * Get a secret directly from Vault (not cached).
 *
 * @param string              $secret Secret name.
 * @param Log\LoggerInterface $logger Optional. A PSR-3 compatible logger to use for errors.
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
 * @throws RuntimeException From `csharpru/vault-php`.
 */
function get_secret_from_vault( string $secret, Log\LoggerInterface $logger = null ) : array {
	$vault = new Vault\Client(
		new VaultTransports\Guzzle6Transport( [
			'base_uri' => get_vault_url(),
		] )
	);

	$vault->setAuthenticationStrategy( new AuthenticationStrategies\TokenAuthenticationStrategy( get_auth_token() ) );

	if ( $logger !== null ) {
		$vault->setLogger( $logger );
	}

	$authenticated = $vault->authenticate();
	if ( $authenticated === false ) {
		throw new RuntimeException( 'Unable to authenticate.' );
	}

	$response = $vault->read( $secret );

	return array_merge(
		$response->getData(),
		[
			'lease_duration' => (int) $response->leaseDuration,  // phpcs:ignore
			'lease_id'       => $response->leaseId,              // phpcs:ignore
		]
	);
}

/**
 * Update a secret before its lease expires.
 *
 * Currently, to renew the lease, we fetch the entire secret again to get a new lease.
 * A future enhancement would be to check if the secret supports `lease_renewable` and,
 * if so, use that to renew the existing lease programatically via Vault's APIs.
 *
 * This function is invoked by wp-cron.
 *
 * @param string $secret Secret name.
 */
function update_secret( string $secret ) : void {
	$deadlock = get_deadlock_name( $secret );

	if ( ! wpdesk_acquire_lock( $secret ) ) {
		$lock_time = (int) get_option( $deadlock, 0 );

		// Handle a potential deadlock.
		if ( $lock_time > 0 && ( time() - $lock_time ) > ( 5 * MINUTE_IN_SECONDS ) ) {
			release_secret_lock( $secret );
		}

		return;
	}

	// Record time the lock was acquired.
	update_option( $deadlock, time(), 'yes' );

	try {
		$data = get_secret_from_vault( $secret );
	} catch ( Exception $error ) {
		release_secret_lock( $secret );
		return;
	}

	set_transient( get_transient_name( $secret ), $data, $data['lease_duration'] - 10 );
	schedule_next_secret_update( $secret, $data );
	release_secret_lock( $secret );
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
function get_transient_name( string $secret ) : string {
	return 'hm_hcvault_vault_' . md5( $secret );
}

/**
 * Get a name for a secret's update lock, based on the Vault secret.
 *
 * Consolidates naming conventions and key length management.
 *
 * @param string $secret Vault secret to use as the base of a transient.
 *
 * @return string
 */
function get_deadlock_name( string $secret ) : string {
	return 'hm_hcvault_deadlock_' . md5( $secret );
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

/**
 * Schedule the next update of a secret.
 *
 * A secret is updated prior to the lease_duration expiring for the current lease.
 * This ensures that the cached secret is always up-to-date and usable.
 *
 * @param string $secret Secret name.
 * @param array  $data   Secret data. See `get_secret_from_vault()`.
 */
function schedule_next_secret_update( string $secret, array $data ) : void {

	// Random reduces likelihood that many keys will start expiring at the same time.
	$timestamp = time() + ( $data['lease_duration'] * 0.8 ) + mt_rand( 0, 30 );

	wp_schedule_single_event(
		(int) $timestamp,
		CRON_OPTION,
		[ $secret ]
	);
}

/**
 * Convenience function to release the update lock for a given secret.
 *
 * @param string $secret Secret name.
 */
function release_secret_lock( string $secret ) : void {
	try {
		wpdesk_release_lock( $secret );
		delete_option( get_deadlock_name( $secret ) );
	} catch ( Mutex\MutexNotFoundInStorage $error ) {
		// No harm done.
	}
}
