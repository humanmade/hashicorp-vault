<?php
/**
 * Plugin Name: HashiCorp Vault integration for WordPress
 * Description: Access Vault secrets, utilising WordPress APIs for maximum scalability.
 * Author: Human Made Limited
 * Author URI: https://humanmade.com
 * License: MIT
 * Version: 0.3.0
 *
 * @package HM\Hashicorp_Vault
 *
 * This integration uses `csharpru/vault-php`, which connects to a HashiCorp Vault service with
 * a HTTP API using token-based authentication, and returns the requested secret. We cache that
 * response using the transients API to avoid large amounts of external HTTP requests.
 *
 * Almost everything in Vault has an associated lease, and when the lease is expired, the secret
 * is revoked. To renew the lease, we fetch the entire secret again to get a new lease. This
 * process is automated with the wp-cron API, and is triggered when a new secret is fetched.
 *
 * To avoid potential race conditions with a cold cache, we use `wpdesk/wp-mutex` which is a
 * concurrency locking library for WordPress. wp-mutex uses MySQL application-level locks.
 */

declare( strict_types = 1 );

namespace HM\Hashicorp_Vault;

require_once __DIR__ . '/inc/functions.php';

// For PHPCS.
if ( function_exists( 'add_action' ) ) {
	add_action( 'muplugins_loaded', __NAMESPACE__ . '\set_up' );
}
