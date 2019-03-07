<table width="100%">
	<tr>
		<td align="left" width="100%" colspan="2">
			<strong>HashiCorp Vault integration for WordPress</strong><br />
			Access Vault secrets, utilising WordPress APIs for maximum scalability.
		</td>
	</tr>
	<tr>
		<td>
			A <strong><a href="https://humanmade.com/">Human Made</a></strong> library.
		</td>
		<td align="center">
			<img src="https://humanmade.com/content/themes/hmnmd/assets/images/hm-logo.svg" width="100" />
		</td>
	</tr>
</table>

[HashiCorp Vault](https://www.vaultproject.io) integration for WordPress is a library which provides access to Vault secrets in a scaleable manner.

It wraps the [CSharpRU/vault-php](https://github.com/CSharpRU/vault-php) library, and uses WordPress' transients API to provide familiar and necessary caching for WordPress developers. The library offers automatic re-fetching of secrets prior to lease expiry.

Current limitations:
 * Only [token-based authentication](https://learn.hashicorp.com/vault/getting-started/authentication#tokens) is supported.
 * Tokens with a renewable lease are not renewed using Vault's API. Instead, this library will refetch the token prior to expiry.

## Installation
This library is distributed as a WordPress plugin. [Install with Composer](https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies), and activate the plugin in the usual way.

## Usage
In `wp-config.php`, define your Vault token:

`define( 'HM_HASHICORP_VAULT_AUTH_TOKEN', 'your-token-123' );`

`define( 'HM_HASHICORP_VAULT_URL', 'https://example.com/your-vault/' );`

You do not need to activate this plugin in wp-admin, but your application does need to load Composer's autoloader when WordPress plugins are being loaded. For example, this could be done via a `mu-plugin` that simply does:

`require_once __DIR__ . '/vendor/autoload.php';`

## License
This project is made availabile with the MIT license.

## Credits
Created by Human Made for enterprise-scale digital experiences. Written by [Paul Gibbs](https://github.com/paulgibbs). Thanks to all [contributors](https://github.com/humanmade/hashicorp-vault/graphs/contributors).
