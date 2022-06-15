# UM Redirect Login and Nonce Log
A debug tool for tracing UM Login Redirects and all WP Redirects. Version 2.2.0 also includes tracing of UM nonce values.

Last redirect status and nonce items are saved in the options table with option name um_redirect_login_log.

## Shortcode
[redirect_login_log]

The shortcode will list the login redirects and nonce values in reverse order with the following items:

1. Time
2. User ID
3. User Name
4. Status
5. Redirect URL / Nonce values
6. By
7. Code
8. Priority Role
9. WP Roles

Reload the page with the shortcode to list actual redirects and nonce values.
## Display failures
1. Remove the shortcode page from UM Restrictions.
2. Disable WP Plugin or web server caching.

## Installation
Install by downloading the ZIP file and install as a new Plugin, 

which you upload in WordPress -> Plugins -> Add New -> Upload Plugin.

Activate the Plugin: Ultimate Member - Redirect Login and Nonce Trace Log

Settings at UM Settings -> Misc

1. Redirect Login/Nonce Log User ID's
2. Redirect Login/Nonce Log max number of log entries 
