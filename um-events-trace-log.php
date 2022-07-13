<?php
/**
 * Plugin Name:     Ultimate Member - Events Trace Log
 * Description:     Extension to Ultimate Member for logging events like redirects during login, UM nonce creation/verification, password reset, email account verification and login errors. Settings at UM Settings -> Misc
 * Version:         3.1.0
 * Requires PHP:    7.4
 * Author:          Miss Veronica
 * License:         GPL v2 or later
 * License URI:     https://www.gnu.org/licenses/gpl-2.0.html
 * Author URI:      https://github.com/MissVeronica
 * Text Domain:     ultimate-member
 * Domain Path:     /languages
 * UM version:      2.4.1
 */

if ( ! defined( 'ABSPATH' ) ) exit; 
if ( ! class_exists( 'UM' ) ) return;

if( !empty( UM()->options()->get( 'events_trace_log_validation' ) ) && isset( UM()->classes['permalinks'] )) {
    remove_action( 'init', array( UM()->classes['permalinks'], 'activate_account_via_email_link'), 1 );
    add_action(    'init', 'activate_account_via_email_link_log', 1 );
}

if( !empty( UM()->options()->get( 'events_trace_log_redirect' ) )) {
    remove_action( 'um_user_login', 'um_user_login', 10 );
    add_action(    'um_user_login', 'um_user_login_log', 10 );

    remove_action( 'um_registration_complete', 'um_check_user_status', 100, 2 );
    add_action(    'um_registration_complete', 'um_check_user_status_log', 100, 2 ); //redirect registration

    add_filter( 'x_redirect_by', 'wp_redirect_login_log', 10, 3 );
}

if( !empty( UM()->options()->get( 'events_trace_log_nonce' ))) {
    add_action( 'wp_verify_nonce_failed', 'wp_verify_nonce_failed_log', 10, 4 );
}

if( !empty( UM()->options()->get( 'events_trace_log_password' )) && isset( UM()->classes['password'] )) {
    remove_action( 'template_redirect', array( UM()->classes['password'], 'form_init' ), 10001 );
    add_action(    'template_redirect', 'form_init_log', 10001 );

    add_action(    'retrieve_password_key',           'retrieve_password_key_log', 10, 2 );
    add_filter(    'x_redirect_by',                   'wp_redirect_password_log', 10, 3 );
    add_action(    'um_after_changing_user_password', 'um_after_changing_user_password_log', 10, 1 );
    add_filter(    'wp_authenticate_user',            'wp_authenticate_user_custom_log', 10, 2 );
    add_action(    'wp_login_failed',                 'wp_login_failed_custom_log', 10, 2 );
}

add_filter(    'um_settings_structure', 'um_settings_structure_misc_log', 10, 1 );
add_shortcode( 'um_events_trace_log',   'um_events_trace_log_shortcode' );




function wp_login_failed_custom_log( $user_name, $wp_error ) {

    if( empty( $user_name )) return;

    my_um_events_trace_log( array(  'status'  => 'login', 
                                    'user_id' => '', 
                                    'info'    => 'attempt by username ' . $user_name ));
}

function wp_authenticate_user_custom_log( $user, $user_password ) {

    if( is_wp_error( $user )) {

        $msg = $user->get_error_code();
        switch( $msg ) {
            case 'incorrect_password':  
            case 'user_password':       $msg .= '=' . $user_password; break;

            case 'invalid_email':
            case 'empty_password':
            case 'empty_username':
            case 'invalid_username':    break;

            default:                    $msg = 'unknown error code=' . $msg;
        }
        my_um_events_trace_log( array(  'status'  => 'login', 
                                        'user_id' => '', 
                                        'info'    => $msg ));
    }
    return $user;
}

/**
 * Password page form
 */
function form_init_log() {
    if ( um_is_core_page( 'password-reset' ) ) {
        UM()->fields()->set_mode = 'password';
    }

    if ( um_is_core_page( 'password-reset' ) && isset( $_REQUEST['act'] ) && 'reset_password' === sanitize_key( $_REQUEST['act'] ) ) {
        wp_fix_server_vars();

        $rp_cookie = 'wp-resetpass-' . COOKIEHASH;

        if ( isset( $_GET['hash'] ) ) {
            $userdata = get_userdata( wp_unslash( absint( $_GET['user_id'] ) ) );
            if ( ! $userdata || is_wp_error( $userdata ) ) {

                my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                               'user_id' => $_GET['user_id'], 
                                               'info'    => 'bad userdata' ));

                wp_redirect( add_query_arg( array( 'act' => 'reset_password', 'error' => 'invalidkey' ), get_permalink() ) );
                exit;
            }
            $rp_login = $userdata->user_login;
            $rp_key = wp_unslash( sanitize_text_field( $_GET['hash'] ) );

            $user = check_password_reset_key( $rp_key, $rp_login );

            if ( is_wp_error( $user ) ) {
                UM()->classes['password']->setcookie( $rp_cookie, false );

                my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                               'user_id' => $_GET['user_id'], 
                                               'info'    => 'wp_error remove rp cookie' ));

                wp_redirect( add_query_arg( array( 'updated' => 'invalidkey' ), get_permalink() ) );

            } else {

                $value = sprintf( '%s:%s', $rp_login, wp_unslash( sanitize_text_field( $_GET['hash'] ) ) );
                UM()->classes['password']->setcookie( $rp_cookie, $value );

                my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                               'user_id' => $_GET['user_id'], 
                                               'info'    => 'set rp cookie to ' . $value ));

                wp_safe_redirect( remove_query_arg( array( 'hash', 'user_id' ) ) );
            }

            exit;
        }

        if ( isset( $_COOKIE[ $rp_cookie ] ) && 0 < strpos( $_COOKIE[ $rp_cookie ], ':' ) ) {
            list( $rp_login, $rp_key ) = explode( ':', wp_unslash( $_COOKIE[ $rp_cookie ] ), 2 );

            my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                           'user_id' => '', 
                                           'info'    => 'rp cookie found ' . $_COOKIE[ $rp_cookie ]));

            $user = check_password_reset_key( $rp_key, $rp_login );

        } else {

            my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                           'user_id' => '', 
                                           'info'    => 'rp cookie ' . $rp_cookie . ' not found or blocked' ));
            $user = false;
        }

        if ( ( ! $user || is_wp_error( $user ) ) && ! isset( $_GET['updated'] ) ) {
            UM()->classes['password']->setcookie( $rp_cookie, false );

            my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                           'user_id' => '', 
                                           'info'    => 'remove rp cookie' ));

            if ( $user && $user->get_error_code() === 'expired_key' ) {
                wp_redirect( add_query_arg( array( 'updated' => 'expiredkey' ), get_permalink() ) );
            } else {
                wp_redirect( add_query_arg( array( 'updated' => 'invalidkey' ), get_permalink() ) );
            }
            exit;
        }

        UM()->classes['password']->change_password = true;
    }

    if ( UM()->classes['password']->is_reset_request() ) {

        UM()->form()->post_form = $_POST;

        if ( empty( UM()->form()->post_form['mode'] ) ) {
            UM()->form()->post_form['mode'] = 'password';
        }

        /**
         * UM hook
         *
         * @type action
         * @title um_reset_password_errors_hook
         * @description Action on reset password submit form
         * @input_vars
         * [{"var":"$post","type":"array","desc":"Form submitted"}]
         * @change_log
         * ["Since: 2.0"]
         * @usage add_action( 'um_reset_password_errors_hook', 'function_name', 10, 1 );
         * @example
         * <?php
         * add_action( 'um_reset_password_errors_hook', 'my_reset_password_errors', 10, 1 );
         * function my_reset_password_errors( $post ) {
         *     // your code here
         * }
         * ?>
         */
        do_action( 'um_reset_password_errors_hook', UM()->form()->post_form );

        if ( ! isset( UM()->form()->errors ) ) {

            /**
             * UM hook
             *
             * @type action
             * @title um_reset_password_process_hook
             * @description Action on reset password success submit form
             * @input_vars
             * [{"var":"$post","type":"array","desc":"Form submitted"}]
             * @change_log
             * ["Since: 2.0"]
             * @usage add_action( 'um_reset_password_process_hook', 'function_name', 10, 1 );
             * @example
             * <?php
             * add_action( 'um_reset_password_process_hook', 'my_reset_password_process', 10, 1 );
             * function my_reset_password_process( $post ) {
             *     // your code here
             * }
             * ?>
             */
            do_action( 'um_reset_password_process_hook', UM()->form()->post_form );

        }
    }

    if ( UM()->classes['password']->is_change_request() ) {
        UM()->form()->post_form = $_POST;

        /**
         * UM hook
         *
         * @type action
         * @title um_change_password_errors_hook
         * @description Action on change password submit form
         * @input_vars
         * [{"var":"$post","type":"array","desc":"Form submitted"}]
         * @change_log
         * ["Since: 2.0"]
         * @usage add_action( 'um_change_password_errors_hook', 'function_name', 10, 1 );
         * @example
         * <?php
         * add_action( 'um_change_password_errors_hook', 'my_change_password_errors', 10, 1 );
         * function my_change_password_errors( $post ) {
         *     // your code here
         * }
         * ?>
         */
        do_action( 'um_change_password_errors_hook', UM()->form()->post_form );

        if ( ! isset( UM()->form()->errors ) ) {

            /**
             * UM hook
             *
             * @type action
             * @title um_change_password_process_hook
             * @description Action on change password success submit form
             * @input_vars
             * [{"var":"$post","type":"array","desc":"Form submitted"}]
             * @change_log
             * ["Since: 2.0"]
             * @usage add_action( 'um_change_password_process_hook', 'function_name', 10, 1 );
             * @example
             * <?php
             * add_action( 'um_change_password_process_hook', 'my_change_password_process', 10, 1 );
             * function my_change_password_process( $post ) {
             *     // your code here
             * }
             * ?>
             */
            do_action( 'um_change_password_process_hook', UM()->form()->post_form );

        }
    }
}


/**
 * Check user status and redirect it after registration
 *
 * @param $user_id
 * @param $args
 */
function um_check_user_status_log( $user_id, $args ) {
	$status = um_user( 'account_status' );

	/**
	 * UM hook
	 *
	 * @type action
	 * @title um_post_registration_{$status}_hook
	 * @description After complete UM user registration.
	 * @input_vars
	 * [{"var":"$user_id","type":"int","desc":"User ID"},
	 * {"var":"$args","type":"array","desc":"Form data"}]
	 * @change_log
	 * ["Since: 2.0"]
	 * @usage add_action( 'um_post_registration_{$status}_hook', 'function_name', 10, 2 );
	 * @example
	 * <?php
	 * add_action( 'um_post_registration_{$status}_hook', 'my_post_registration', 10, 2 );
	 * function my_post_registration( $user_id, $args ) {
	 *     // your code here
	 * }
	 * ?>
	 */
	do_action( "um_post_registration_{$status}_hook", $user_id, $args );

	if ( ! is_admin() ) {

		do_action( "track_{$status}_user_registration" );

		if ( $status == 'approved' ) {

			UM()->user()->auto_login( $user_id );
			UM()->user()->generate_profile_slug( $user_id );

			/**
			 * UM hook
			 *
			 * @type action
			 * @title um_registration_after_auto_login
			 * @description After complete UM user registration and autologin.
			 * @input_vars
			 * [{"var":"$user_id","type":"int","desc":"User ID"}]
			 * @change_log
			 * ["Since: 2.0"]
			 * @usage add_action( 'um_registration_after_auto_login', 'function_name', 10, 1 );
			 * @example
			 * <?php
			 * add_action( 'um_registration_after_auto_login', 'my_registration_after_auto_login', 10, 1 );
			 * function my_registration_after_auto_login( $user_id ) {
			 *     // your code here
			 * }
			 * ?>
			 */
			do_action( 'um_registration_after_auto_login', $user_id );

			// Priority redirect
			if ( isset( $args['redirect_to'] ) ) {
				my_um_trace_events_prelog( 'prio redirect', $args['redirect_to'] );
                exit( wp_safe_redirect( urldecode( $args['redirect_to'] ) ) );
			}

			um_fetch_user( $user_id );

			if ( um_user( 'auto_approve_act' ) == 'redirect_url' && um_user( 'auto_approve_url' ) !== '' ) {
                my_um_trace_events_prelog( 'auto_approve', 'redirect_url: ' . um_user( 'auto_approve_url' ) );
				exit( wp_redirect( um_user( 'auto_approve_url' ) ) );
			}

			if ( um_user( 'auto_approve_act' ) == 'redirect_profile' ) {
				my_um_trace_events_prelog( 'auto_approve', 'redirect_profile: ' . um_user( 'auto_approve_url' ) );
                exit( wp_redirect( um_user_profile_url() ) );
			}

		} else {

			if ( um_user( $status . '_action' ) == 'redirect_url' && um_user( $status . '_url' ) != '' ) {
				/**
				 * UM hook
				 *
				 * @type filter
				 * @title um_registration_pending_user_redirect
				 * @description Change redirect URL for pending user after registration
				 * @input_vars
				 * [{"var":"$url","type":"string","desc":"Redirect URL"},
				 * {"var":"$status","type":"string","desc":"User status"},
				 * {"var":"$user_id","type":"int","desc":"User ID"}]
				 * @change_log
				 * ["Since: 2.0"]
				 * @usage
				 * <?php add_filter( 'um_registration_pending_user_redirect', 'function_name', 10, 3 ); ?>
				 * @example
				 * <?php
				 * add_filter( 'um_registration_pending_user_redirect', 'my_registration_pending_user_redirect', 10, 3 );
				 * function my_registration_pending_user_redirect( $url, $status, $user_id ) {
				 *     // your code here
				 *     return $url;
				 * }
				 * ?>
				 */
                my_um_trace_events_prelog( 'auto_approve', $status . '_url to filter: ' . um_user( $status . '_url' ) );
				$redirect_url = apply_filters( 'um_registration_pending_user_redirect', um_user( $status . '_url' ), $status, um_user( 'ID' ) );
                my_um_trace_events_prelog( 'auto_approve', 'from filter: ' . $redirect_url );
				exit( wp_redirect( $redirect_url ) );
			}

			if ( um_user( $status . '_action' ) == 'show_message' && um_user( $status . '_message' ) != '' ) {

				$url  = UM()->permalinks()->get_current_url();
				$url  = add_query_arg( 'message', esc_attr( $status ), $url );
				//add only priority role to URL
				$url  = add_query_arg( 'um_role', esc_attr( um_user( 'role' ) ), $url );
				$url  = add_query_arg( 'um_form_id', esc_attr( $args['form_id'] ), $url );
                my_um_trace_events_prelog( 'auto_approve', 'show_message: ' . $url );
				exit( wp_redirect( $url ) );
			}
		}
	}
}


/**
 * Activates an account via email
 */
function activate_account_via_email_link_log() {
    if ( isset( $_REQUEST['act'] ) && 'activate_via_email' === sanitize_key( $_REQUEST['act'] ) && isset( $_REQUEST['hash'] ) && is_string( $_REQUEST['hash'] ) && strlen( $_REQUEST['hash'] ) == 40 &&
            isset( $_REQUEST['user_id'] ) && is_numeric( $_REQUEST['user_id'] ) ) { // valid token

        $user_id = absint( $_REQUEST['user_id'] );
        delete_option( "um_cache_userdata_{$user_id}" );
        $account_secret_hash = get_user_meta( $user_id, 'account_secret_hash', true );

        my_um_events_trace_log( array( 'status'  => 'activate', 
                                       'user_id' => $user_id, 
                                       'info'    => 'code from email ' . sanitize_text_field( $_REQUEST['hash'] ) ));

        if( empty( $account_secret_hash )) $valid = 'Activation code already used';
        else $valid = 'code is valid ' . $account_secret_hash;

        my_um_events_trace_log( array( 'status'  => 'activate', 
                                       'user_id' => $user_id, 
                                       'info'    => $valid ));

        if ( empty( $account_secret_hash ) || strtolower( sanitize_text_field( $_REQUEST['hash'] ) ) !== strtolower( $account_secret_hash ) ) {
            wp_die( __( 'This activation link is expired or have already been used.', 'ultimate-member' ) );
        }

        $account_secret_hash_expiry = get_user_meta( $user_id, 'account_secret_hash_expiry', true );

        my_um_events_trace_log( array( 'status'  => 'activate', 
                                       'user_id' => $user_id, 
                                       'info'    => 'expire ' . date_i18n( "Y-m-d H:i:s", $account_secret_hash_expiry ) ));

        if ( ! empty( $account_secret_hash_expiry ) && time() > $account_secret_hash_expiry ) {
            wp_die( __( 'This activation link is expired.', 'ultimate-member' ) );
        }

        um_fetch_user( $user_id );
        UM()->user()->approve();
        um_reset_user();

        $user_role = UM()->roles()->get_priority_user_role( $user_id );
        $user_role_data = UM()->roles()->role_data( $user_role );

        // log in automatically
        $login = ! empty( $user_role_data['login_email_activate'] ); // Role setting "Login user after validating the activation link?"
        if ( ! is_user_logged_in() && $login ) {
            $user = get_userdata( $user_id );

            // update wp user
            wp_set_current_user( $user_id, $user->user_login );
            wp_set_auth_cookie( $user_id );

            ob_start();
            do_action( 'wp_login', $user->user_login, $user );
            ob_end_clean();
        }

        /**
         * UM hook
         *
         * @type action
         * @title um_after_email_confirmation
         * @description Action on user activation
         * @input_vars
         * [{"var":"$user_id","type":"int","desc":"User ID"}]
         * @change_log
         * ["Since: 2.0"]
         * @usage add_action( 'um_after_email_confirmation', 'function_name', 10, 1 );
         * @example
         * <?php
         * add_action( 'um_after_email_confirmation', 'my_after_email_confirmation', 10, 1 );
         * function my_after_email_confirmation( $user_id ) {
         *     // your code here
         * }
         * ?>
         */
        do_action( 'um_after_email_confirmation', $user_id );

        $redirect = empty( $user_role_data['url_email_activate'] ) ? um_get_core_page( 'login', 'account_active' ) : trim( $user_role_data['url_email_activate'] ); // Role setting "URL redirect after e-mail activation"
        $redirect = apply_filters( 'um_after_email_confirmation_redirect', $redirect, $user_id, $login );

        exit( wp_redirect( $redirect ) );

    }
}


if ( ! function_exists( 'wp_verify_nonce' ) && !empty( UM()->options()->get( 'events_trace_log_nonce' ))) :
	/**
	 * Verifies that a correct security nonce was used with time limit.
	 *
	 * A nonce is valid for 24 hours (by default).
	 *
	 * @since 2.0.3
	 *
	 * @param string     $nonce  Nonce value that was used for verification, usually via a form field.
	 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
	 * @return int|false 1 if the nonce is valid and generated between 0-12 hours ago,
	 *                   2 if the nonce is valid and generated between 12-24 hours ago.
	 *                   False if the nonce is invalid.
	 */

	function wp_verify_nonce( $nonce, $action = -1 ) {
		$nonce = (string) $nonce;
		$user  = wp_get_current_user();
		$uid   = (int) $user->ID;
		if ( ! $uid ) {
			/**
			 * Filters whether the user who generated the nonce is logged out.
			 *
			 * @since 3.5.0
			 *
			 * @param int    $uid    ID of the nonce-owning user.
			 * @param string $action The nonce action.
			 */
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		if ( empty( $nonce ) ) {
            if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
                my_um_events_trace_log( array( 'status'  => 'unverified', 
                                               'user_id' => $uid, 
                                               'nonce'   => 'Empty', 
                                               'action'  => $action, 
                                               'token'   => '', 
                                               'tick'    => '' ));
            }
			return false;
		}

		$token = wp_get_session_token();
		$i     = wp_nonce_tick();

		// Nonce generated 0-12 hours ago.
		$expected = substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {

            if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
                my_um_events_trace_log( array( 'status'  => 'verified 12', 
                                               'user_id' => $uid, 
                                               'nonce'   => $nonce, 
                                               'action'  => $action, 
                                               'token'   => $token, 
                                               'tick'    => $i ));
            }
			return 1;
		}

		// Nonce generated 12-24 hours ago.
		$expected = substr( wp_hash( ( $i - 1 ) . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {

            if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
                my_um_events_trace_log( array( 'status'  => 'verified 24', 
                                               'user_id' => $uid, 
                                               'nonce'   => $nonce, 
                                               'action'  => $action, 
                                               'token'   => $token, 
                                               'tick'    => $i ));
            }
			return 2;
		}

		/**
		 * Fires when nonce verification fails.
		 *
		 * @since 4.4.0
		 *
		 * @param string     $nonce  The invalid nonce.
		 * @param string|int $action The nonce action.
		 * @param WP_User    $user   The current user object.
		 * @param string     $token  The user's session token.
		 */
		do_action( 'wp_verify_nonce_failed', $nonce, $action, $user, $token );

		// Invalid nonce.
		return false;
	}
endif;

if ( ! function_exists( 'wp_create_nonce' ) && !empty( UM()->options()->get( 'events_trace_log_nonce' ))) :
	/**
	 * Creates a cryptographic token tied to a specific action, user, user session,
	 * and window of time.
	 *
	 * @since 2.0.3
	 * @since 4.0.0 Session tokens were integrated with nonce creation
	 *
	 * @param string|int $action Scalar value to add context to the nonce.
	 * @return string The token.
	 */
	function wp_create_nonce( $action = -1 ) {
		$user = wp_get_current_user();
		$uid  = (int) $user->ID;
		if ( ! $uid ) {
			/** This filter is documented in wp-includes/pluggable.php */
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		$token = wp_get_session_token();
		$i     = wp_nonce_tick();

        $nonce = substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );

        if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
            my_um_events_trace_log( array( 'status'  => 'create', 
                                           'user_id' => $uid, 
                                           'nonce'   => $nonce, 
                                           'action'  => $action, 
                                           'token'   => $token, 
                                           'tick'    => $i ));
        }

        return $nonce;
	}
endif;

if ( ! function_exists( 'wp_nonce_tick' && !empty( UM()->options()->get( 'events_trace_log_nonce' )))) :
	/**
	 * Returns the time-dependent variable for nonce creation.
	 *
	 * A nonce has a lifespan of two ticks. Nonces in their second tick may be
	 * updated, e.g. by autosave.
	 *
	 * @since 2.5.0
	 *
	 * @return float Float value rounded up to the next highest integer.
	 */
	function wp_nonce_tick() {
		/**
		 * Filters the lifespan of nonces in seconds.
		 *
		 * @since 2.5.0
		 *
		 * @param int $lifespan Lifespan of nonces in seconds. Default 86,400 seconds, or one day.
		 */
		$nonce_life = apply_filters( 'nonce_life', DAY_IN_SECONDS );

		return ceil( time() / ( $nonce_life / 2 ) );
	}
endif;

function wp_verify_nonce_failed_log( $nonce, $action, $user, $token ) {

    if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
       my_um_events_trace_log( array( 'status'  => 'reject', 
                                      'user_id' => $user->ID, 
                                      'action'  => $action, 
                                      'nonce'   => $nonce, 
                                      'token'   => $token, 
                                      'tick'    => '' ));
    }
}

function um_user_login_log( $args ) {

    extract( $args );

    $rememberme = ( isset( $args['rememberme'] ) && 1 == $args['rememberme'] && isset( $_REQUEST['rememberme'] ) ) ? 1 : 0;

    if ( ( UM()->options()->get( 'deny_admin_frontend_login' ) && ! isset( $_GET['provider'] ) ) && strrpos( um_user('wp_roles' ), 'administrator' ) !== false ) {
        wp_die( esc_html__( 'This action has been prevented for security measures.', 'ultimate-member' ) );
    }

    UM()->user()->auto_login( um_user( 'ID' ), $rememberme );

    do_action( 'um_on_login_before_redirect', um_user( 'ID' ) );

    // Priority redirect
    if ( ! empty( $args['redirect_to']  ) ) {
        my_um_trace_events_prelog( 'prio redirect', $args['redirect_to'] );
        exit( wp_safe_redirect( $args['redirect_to'] ) );
    }

    // Role redirect
    $after_login = um_user( 'after_login' );
    if ( empty( $after_login ) ) {
        my_um_trace_events_prelog( 'role redirect', um_user_profile_url() );
        exit( wp_redirect( um_user_profile_url() ) );
    }

    switch ( $after_login ) {

        case 'redirect_admin':
            my_um_trace_events_prelog( 'redirect_admin', admin_url() );
            exit( wp_redirect( admin_url() ) );
            break;

        case 'redirect_url':
            my_um_trace_events_prelog( 'redirect_url', 'to filter: ' . um_user( 'login_redirect_url' ) );
            $redirect_url = apply_filters( 'um_login_redirect_url', um_user( 'login_redirect_url' ), um_user( 'ID' ) );
            my_um_trace_events_prelog( 'redirect_url', 'from filter: ' . $redirect_url );
            exit( wp_redirect( $redirect_url ) );
            break;

        case 'refresh':
            my_um_trace_events_prelog( 'refresh', UM()->permalinks()->get_current_url() );
            exit( wp_redirect( UM()->permalinks()->get_current_url() ) );
            break;

        case 'redirect_profile':
        default:
            my_um_trace_events_prelog( 'after login', um_user_profile_url() );
            exit( wp_redirect( um_user_profile_url() ) );
            break;
	}
}

function wp_redirect_by_login_log() {

    $traces = debug_backtrace( DEBUG_BACKTRACE_PROVIDE_OBJECT );
    $plugin_trace = array();

    foreach( $traces as $trace ) {
        if( strpos( $trace['file'], '/plugins/' ) > 0 ) {
            $file = explode( '/plugins/', $trace['file'] );
            if( substr( $file[1], 0, 19 ) != 'um-events-trace-log' ) {
                $plugin_trace[] = $file[1] . ':' . $trace['line'];
            }
        }
    }
    return implode( ', ', $plugin_trace );
}

function my_um_trace_events_prelog( $status, $redirect ) {

    $array = array( 'status'      => $status, 
                    'redirect'    => $redirect,
                    'redirect_by' => wp_redirect_by_login_log() );
 
    my_um_events_trace_log( $array );
}

function wp_redirect_login_log( $x_redirect_by, $status, $location ) {



    my_um_events_trace_log( array( 'status'      => 'wp_redirect', 
                                   'redirect'    => $location, 
                                   'redirect_by' => wp_redirect_by_login_log(), 
                                   'code'        => $status ));

    return $x_redirect_by;
}

function um_after_changing_user_password_log( $user_id ) {

    my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                   'user_id' => $user_id, 
                                   'info'    => 'Password updated by user, the hash now obsolete.' ));
}

function wp_redirect_password_log( $x_redirect_by, $status, $location ) {

    if( isset( $_GET['act'] ) && $_GET['act'] == 'reset_password' && isset( $_GET['hash'] )) {

        if( strpos( $location, 'updated=invalidkey' )) $get = 'get email invalid hash ';
        else $get = 'get email hash ';

        my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                       'user_id' => $_GET['user_id'], 
                                       'info'    => $get . $_GET['hash'] ));
    }

    return $x_redirect_by;
}

function retrieve_password_key_log( $user_login, $key ) {

    $user = get_user_by( 'login', $user_login );

    my_um_events_trace_log( array( 'status'  => 'reset_pwd', 
                                   'user_id' => $user->ID, 
                                   'info'    => 'create new hash ' . $key ));
}

function my_um_events_trace_log( $array ) {

    global $current_user;

    if( empty( UM()->options()->get( 'events_trace_log_user_id' )) && empty( UM()->options()->get( 'events_trace_log_user_ip' ))) return;

    if( $current_user->ID > 0 )         $user_id = $current_user->ID;
    elseif( !empty( um_user( 'ID' )))   $user_id = um_user( 'ID' );
    elseif( isset( $array['user_id'] )) $user_id = $array['user_id'];
    else $user_id = '';
    if( $user_id == 0 ) $user_id = '';

    if( empty( $user_id ) || 
        UM()->options()->get( 'events_trace_log_user_id' ) == '@' ||
        in_array( $user_id, explode( ',', UM()->options()->get( 'events_trace_log_user_id' )))) {

        if( empty( UM()->options()->get( 'events_trace_log_user_ip' )) || 
            in_array( um_user_ip(), explode( ',', UM()->options()->get( 'events_trace_log_user_ip' )))) {

            $log = get_option( 'um_events_trace_log' );
            if( empty( $log ) || !isset( $log['data'] )) $log = array( 'time' => array(), 'data' => array());

            $provider = '';
            if( isset( $_GET['provider'] ))        $provider = sanitize_text_field( $_GET['provider'] );
            if( !empty( $array['x_redirect_by'] )) $provider = $array['x_redirect_by'];

            $user_meta = get_userdata( $user_id );
            if( isset( $user_meta->user_login )) $user_login = $user_meta->user_login; else $user_login = '';
            if( isset( $user_meta->roles ))      $user_roles = $user_meta->roles; else $user_roles = array();

            $array = array_merge( $array, array( 'user_id'    => $user_id,
                                                 'user_login' => $user_login,
                                                 'IP'         => um_user_ip(),
                                                 'um_role'    => UM()->roles()->get_priority_user_role( $user_id ),
                                                 'wp_roles'   => implode( ', ', $user_roles ),
                                                 'provider'   => $provider
                                                ));

            if( isset( $array['token'] ) && empty( $array['token'] )) $array['token'] = 'No session';

            $found = false;
            $new = serialize( $array );
            $time_window = current_time( 'timestamp' ) - 3;

            foreach( $log['time'] as $key => $timestamp ) {
                if( $time_window < $timestamp ) {
                    if( serialize( $log['data'][$key] ) == $new ) {
                        $found = true;
                        break;
                    }
                } else break;
            }

            if( !$found ) {

                $max_items = (int)UM()->options()->get( 'events_trace_log_max_items' );
                if( empty( $max_items )) $max_items = 100;
                if( $max_items > 300 )   $max_items = 300;

                while(  count( $log['data'] ) > $max_items - 1 ) {
                    array_pop( $log['data'] );
                    array_pop( $log['time'] );
                }

                array_unshift( $log['data'], $array );
                array_unshift( $log['time'], current_time( 'timestamp' ) );

                update_option( 'um_events_trace_log', $log, false );
            }
        }
    }
}

function um_events_trace_log_shortcode( $atts ) {

    if( current_user_can( 'administrator' )) {

        $log = get_option( 'um_events_trace_log' );
        if( empty( $log ) || !isset( $log['data'] )) $log = array( 'time' => array(), 
                                                                   'data' => array());

        $html_codes = array( '300' => __( 'Multiple Choices 	A link list. The user can select a link and go to that location. Maximum five addresses', 'ultimate-member' ),  
                             '301' => __( 'Moved Permanently 	The requested page has moved to a new URL', 'ultimate-member' ),
                             '302' => __( 'Found 	The requested page has moved temporarily to a new URL', 'ultimate-member' ), 
                             '303' => __( 'See Other 	The requested page can be found under a different URL', 'ultimate-member' ),
                             '304' => __( 'Not Modified 	Indicates the requested page has not been modified since last requested', 'ultimate-member' ),
                             '307' => __( 'Temporary Redirect 	The requested page has moved temporarily to a new URL', 'ultimate-member' ),
                             '308' => __( 'Permanent Redirect   The requested page has moved permanently to a new URL', 'ultimate-member' ));

        ob_start();
        echo '<h4>' . sprintf( __( 'UM Events Trace Log, version %s', 'ultimate-member' ), '3.1') . '</h4>';
        echo '<h4>' . sprintf( __( 'Display of last %d log entries in reverse order %s', 'ultimate-member' ), esc_html( count( $log['time'] )), esc_html( date_i18n( "Y-m-d H:i:s", current_time( 'timestamp' ) ))) . '</h4>';
        echo '<h5>' . __( 'If refresh of this page will not display new values during your test: Turn off WP Plugin and Web Hosting caching for the UM Pages and Clear Browser cache.', 'ultimate-member' ) . '</h5>';

        if( !empty( $log['data'] )) {

            echo '<div style="display: table-row;">
                  <div style="display: table-cell;" title="Time in Hours 00-24, Minutes, Seconds. Date in Year, Month, Day">' . __( 'Time', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'ID', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'User', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'IP', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Status', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Redirect URL / Nonce / Reset pwd / Activation Hash / Login', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Redirect by script: line', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'HTML Code', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Priority Role', 'ultimate-member' ) . '</div>
                  </div>';

            foreach( $log['time'] as $key => $timestamp ) {

                echo '<div style="display: table-row;">
                        <div style="display: table-cell;" title="Date ' . esc_html( date_i18n( "Y-m-d", $timestamp )) . '">' . esc_html( date_i18n( "H:i:s", $timestamp )) . '</div>';

                $item = $log['data'][$key];

                switch( $item['status'] ) {
                    case 'create':          $action = 'title="Create a page nonce"'; break;
                    case 'login':           $action = 'title="Username or password invalid at login"'; break;
                    case 'verified 12':     $action = 'title="Nonce OK, generated 0-12 hours ago."'; break;
                    case 'verified 24':     $action = 'title="Nonce OK, generated 12-24 hours ago."'; break;
                    case 'reject':          $action = 'title="Nonce failed (older than 24 hours). Do you have any WP plugin or web hosting caching active?"'; break;
                    case 'redirect_url':    $action = 'title="Redirect URL before and after call to the &quot;um_login_redirect_url&quot; filter"'; break;
                    case 'after login':     $action = 'title="Default redirect after login"'; break;
                    case 'prio redirect':   $action = 'title="Priority redirect after login or registration"'; break;
                    case 'reset_pwd':       $action = 'title="Verify that created hash and email hash are equal. Hash is obsolete after a password change."'; break;
                    default:                $action = '';
                }

                $line = '<div style="display: table-cell; padding:0px 0px 0px 8px;">' . esc_html( $item['user_id'] ) . '</div>
                         <div style="display: table-cell; padding:0px 0px 0px 8px;">' . esc_html( $item['user_login'] ) . '</div>
                         <div style="display: table-cell; padding:0px 0px 0px 8px;">' . esc_html( $item['IP'] ) . '</div>                    
                         <div style="display: table-cell; padding:0px 0px 0px 8px;" ' . $action . '>' . esc_html( $item['status'] ) . '</div>';

                switch( $item['status'] ) {

                    case 'reject':
                    case 'create':          $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="Session token ' . esc_html( $item['token'] ) . 
                                                     ' Tick ' . esc_html( $item['tick'] ) . '">' . esc_html( $item['action'] ) . ' ' . esc_html( $item['nonce'] ) . '</div>
                                                      <div style="display: table-cell;"></div>
                                                      <div style="display: table-cell;"></div>';
                                            break;

                    case 'activate':
                    case 'reset_pwd':       $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['info'] ) . '</div>
                                                      <div style="display: table-cell;"></div>
                                                      <div style="display: table-cell;"></div>';
                                            break;

                    case 'wp_redirect':     if( isset( $item['code'] ) && !empty( $item['code'] )) $code = esc_html( $item['code'] ) . ' ' . esc_html( $html_codes[$item['code']] );
                                            else $code = '';

                                            if( isset( $item['redirect_by'] ) && $item['redirect_by'] == 'WordPress' ) $item['redirect_by'] = 'WP';

                                            $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['redirect'] ) . '</div>';
                                            $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['redirect_by'] ) . '</div>';
                                            $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="' . $code . '">' . esc_html( $item['code'] ) . '</div>';
                                            break;

                    case 'auto_approve':
                    case 'prio redirect':
                    case 'role redirect':
                    case 'redirect_admin':
                    case 'refresh':
                    case 'after login':
                    case 'redirect_url':    $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['redirect'] ) . '</div>
                                                      <div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['redirect_by'] ) . '</div>
                                                      <div style="display: table-cell;"></div>';
                                            break;                   

                    case 'unverified':
                    case 'verified 12':
                    case 'verified 24':     $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['nonce'] ) . '</div>
                                                      <div style="display: table-cell;"></div>
                                                      <div style="display: table-cell;"></div>';
                                            break;

                    case 'login':           $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="">' . esc_html( $item['info'] ) . '</div>
                                                      <div style="display: table-cell;"></div>
                                                      <div style="display: table-cell;"></div>';
                                            break;
                } 

                $line .= '<div style="display: table-cell; padding:0px 0px 0px 8px;" title="All WP Roles: ' . esc_html( $item['wp_roles'] ) . '">' . esc_html( $item['um_role'] ) . '</div>';
                $line .= '</div>';

                echo $line;
            }

        } else echo '<div>' . __( 'No Posts', 'ultimate-member' ) . '</div>';
    } else echo '<div>' . __( 'This is not possible for security reasons.', 'ultimate-member' ) . '</div>';

    $output = ob_get_contents();
    ob_end_clean();

    return $output;
}

function um_settings_structure_misc_log( $settings_structure ) {

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_user_id',
                                                     'type'    => 'text',
                                                     'label'   => __( "Events Trace Log User ID's or @", 'ultimate-member' ),
                                                     'tooltip' => __( "Enter comma separated User ID's as integer numbers or @ for all user ID's. Not logged in users (without user ID) will always be logged.", 'ultimate-member' ),
                                                     'size'    => 'short' );
                                                     
    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_user_ip',
                                                     'type'    => 'text',
                                                     'label'   => __( "Events Trace Log User IP addresses", 'ultimate-member' ),
                                                     'tooltip' => __( "Enter IP addresses comma separated or leave this field empty.", 'ultimate-member' ));

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_max_items',
                                                     'type'    => 'text',
                                                     'label'   => __( 'Events Trace Log max number of log entries', 'ultimate-member' ),
                                                     'tooltip' => __( 'Enter a single integer number (typical values between 100 and 300 with more user ID\'s)', 'ultimate-member' ),
                                                     'size'    => 'short' );                                                 

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_nonce',
                                                     'type'    => 'checkbox',
                                                     'label'   => __( 'Log nonce events', 'ultimate-member' ),
                                                     'tooltip' => __( 'Tick to activate this event log', 'ultimate-member' ));  

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_redirect',
                                                     'type'    => 'checkbox',
                                                     'label'   => __( 'Log redirect events', 'ultimate-member' ),
                                                     'tooltip' => __( 'Tick to activate this event log', 'ultimate-member' ));

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_password',
                                                     'type'    => 'checkbox',
                                                     'label'   => __( 'Log password reset events and login errors', 'ultimate-member' ),
                                                     'tooltip' => __( 'Tick to activate this event log', 'ultimate-member' ));

    $settings_structure['misc']['fields'][] = array( 'id'      => 'events_trace_log_validation',
                                                     'type'    => 'checkbox',
                                                     'label'   => __( 'Log email validation events', 'ultimate-member' ),
                                                     'tooltip' => __( 'Tick to activate this event log', 'ultimate-member' ));
    return $settings_structure;
}
