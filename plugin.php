<?php
/**
 * Plugin Name: HashiCorp Vault integration for WordPress
 * Description: Access Vault secrets, utilising WordPress APIs for maximum scalability.
 * Author: Human Made Limited
 * Author URI: https://humanmade.com
 * License: MIT
 * Version: 0.1.0
 */

declare( strict_types = 1 );

namespace HM\Hashicorp_Vault;

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/inc/functions.php';

add_action( 'muplugins_loaded', __NAMESPACE__ . '\set_up' );
