<?php
/**
 * Plugin Name:     Ultimate Member - Redirect Login and Nonce Trace Log
 * Description:     Extension to Ultimate Member for logging all redirects during login and UM nonce creation/verification. Settings at UM Settings -> Misc
 * Version:         2.0.0
 * Requires PHP:    7.4
 * Author:          Miss Veronica
 * License:         GPL v2 or later
 * License URI:     https://www.gnu.org/licenses/gpl-2.0.html
 * Author URI:      https://github.com/MissVeronica
 * Text Domain:     ultimate-member
 * Domain Path:     /languages
 * UM version:      2.3.2
 */

if ( ! defined( 'ABSPATH' ) ) exit; 
if ( ! class_exists( 'UM' ) ) return;

add_action(    'um_user_login',          'um_user_login_trace', 9 );
add_filter(    'x_redirect_by',          'wp_redirect_login_log', 10, 3 );
add_shortcode( 'redirect_login_log',     'redirect_login_log_shortcode' );
remove_action( 'um_user_login',          'um_user_login', 10 );
add_action(    'wp_verify_nonce_failed', 'wp_verify_nonce_failed_log', 10, 4 );
add_filter(    'um_settings_structure',  'um_settings_structure_misc_redirect_log', 10, 1 ); 

if ( ! function_exists( 'wp_verify_nonce' ) ) :
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
                my_um_redirect_login_log( 'unverified', array( 'uid' => $uid, 'nonce' => 'Empty', 'action' => $action, 'token' => '', 'tick' => '' ));
            }
			return false;
		}

		$token = wp_get_session_token();
		$i     = wp_nonce_tick();

		// Nonce generated 0-12 hours ago.
		$expected = substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {

            if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
                my_um_redirect_login_log( 'verified 1', array( 'uid' => $uid, 'nonce' => $nonce, 'action' => $action, 'token' => $token, 'tick' => $i ));
            }
			return 1;
		}

		// Nonce generated 12-24 hours ago.
		$expected = substr( wp_hash( ( $i - 1 ) . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {

            if( in_array( substr( $action, 0, 3 ), array( 'um-', 'um_' )) || strpos( $action, 'um-download-nonce' ) > 0 ) {
                my_um_redirect_login_log( 'verified 2', array( 'uid' => $uid, 'nonce' => $nonce, 'action' => $action, 'token' => $token, 'tick' => $i ));
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

if ( ! function_exists( 'wp_create_nonce' ) ) :
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
            my_um_redirect_login_log( 'create', array( 'uid' => $uid, 'nonce' => $nonce, 'action' => $action, 'token' => $token, 'tick' => $i ));
        }

        return $nonce;
	}
endif;

if ( ! function_exists( 'wp_nonce_tick' ) ) :
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
        my_um_redirect_login_log( 'reject', array( 'uid' => $user->ID, 'action' => $action, 'nonce' => $nonce, 'token' => $token, 'tick' => '' ));
    }
}

function um_user_login_trace( $args ) {

    extract( $args );

    $rememberme = ( isset( $args['rememberme'] ) && 1 == $args['rememberme'] && isset( $_REQUEST['rememberme'] ) ) ? 1 : 0;

    if ( ( UM()->options()->get( 'deny_admin_frontend_login' ) && ! isset( $_GET['provider'] ) ) && strrpos( um_user('wp_roles' ), 'administrator' ) !== false ) {
        wp_die( esc_html__( 'This action has been prevented for security measures.', 'ultimate-member' ) );
    }

    UM()->user()->auto_login( um_user( 'ID' ), $rememberme );

    do_action( 'um_on_login_before_redirect', um_user( 'ID' ) );

    // Priority redirect
    if ( ! empty( $args['redirect_to']  ) ) {
        my_um_redirect_login_log( 'UM Priority redirect', $args['redirect_to'] );
        exit( wp_safe_redirect( $args['redirect_to'] ) );
    }

    // Role redirect
    $after_login = um_user( 'after_login' );
    if ( empty( $after_login ) ) {
        my_um_redirect_login_log( 'UM Role redirect', um_user_profile_url() );
        exit( wp_redirect( um_user_profile_url() ) );
    }

    switch ( $after_login ) {

        case 'redirect_admin':
            my_um_redirect_login_log( 'UM redirect_admin', admin_url() );
            exit( wp_redirect( admin_url() ) );
            break;

        case 'redirect_url':
            my_um_redirect_login_log( 'UM redirect_url filterin', um_user( 'login_redirect_url' ) );
            $redirect_url = apply_filters( 'um_login_redirect_url', um_user( 'login_redirect_url' ), um_user( 'ID' ) );
            my_um_redirect_login_log( 'UM redirect_url filterout', $redirect_url );
            exit( wp_redirect( $redirect_url ) );
            break;

        case 'refresh':
            my_um_redirect_login_log( 'UM refresh', UM()->permalinks()->get_current_url() );
            exit( wp_redirect( UM()->permalinks()->get_current_url() ) );
            break;

        case 'redirect_profile':
        default:
            my_um_redirect_login_log( 'UM ' . $after_login, um_user_profile_url() );
            exit( wp_redirect( um_user_profile_url() ) );
            break;
	}
}

function wp_redirect_login_log( $x_redirect_by, $status, $location ) {

    my_um_redirect_login_log( 'wp_redirect', $location, $x_redirect_by, $status );

    return $x_redirect_by;
}

function my_um_redirect_login_log( $status, $redirect, $x_redirect_by = '', $code = '' ) {

    global $current_user;

    if( empty( UM()->options()->get( 'redirect_log_user_id' ) )) return;

    if( $current_user->ID > 0 ) $user_id = $current_user->ID;
    elseif( !empty( um_user( 'ID' ))) $user_id = um_user( 'ID' );
    else $user_id = '';

    if( empty( $user_id ) || in_array( $user_id, explode( ',', UM()->options()->get( 'redirect_log_user_id' )))) {

        $log = get_option( 'um_redirect_login_log' );
        if( empty( $log ) || !isset( $log['data'] )) $log = array( 'time' => array(), 'data' => array());

        $provider = '';
        if( isset( $_GET['provider'] )) $provider = sanitize_text_field( $_GET['provider'] );
        if( !empty( $x_redirect_by ))   $provider = $x_redirect_by;

        $user_meta = get_userdata( $user_id );
        if( isset( $user_meta->user_login )) $user_login = $user_meta->user_login; else $user_login = '';
        if( isset( $user_meta->roles )) $user_roles = $user_meta->roles; else $user_roles = array();

        $data = array(  $user_id, 
                        $user_login,
                        $status, 
                        $redirect, 
                        $provider,
                        $code,                     
                        UM()->roles()->get_priority_user_role( $user_id ),
                        implode( ', ', $user_roles ),
                    );

        $found = false;
        $new = serialize( $data );
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

            $max_items = (int)UM()->options()->get( 'redirect_log_max_items' );
            if( empty( $max_items )) $max_items = 100;
            if( $max_items > 300 )   $max_items = 300;

            while( count( $log['data'] ) > $max_items - 1 ) {
                array_pop( $log['data'] );
                array_pop( $log['time'] );
            }

            array_unshift( $log['data'], $data );
            array_unshift( $log['time'], current_time( 'timestamp' ) );

            update_option( 'um_redirect_login_log', $log, false );
        }
    }
}

function redirect_login_log_shortcode( $atts ) {

    if( current_user_can( 'administrator' )) {

        $log = get_option( 'um_redirect_login_log' );
        if( empty( $log ) || !isset( $log['data'] )) $log = array( 'time' => array(), 'data' => array());

        ob_start();
        echo '<h4>' . sprintf( __( 'Redirect Login and Nonce Trace Log in reverse order version 2.0 ( %d entries )', 'ultimate-member' ), esc_html( count( $log['time'] ))) . '</h4>';

        if( !empty( $log['data'] )) {

            echo '<div style="display: table-row;">
                  <div style="display: table-cell;">' . __( 'Time', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'ID', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'User', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Status', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Redirect URL / Nonce', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'By', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Code', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'Priority Role', 'ultimate-member' ) . '</div>
                  <div style="display: table-cell; padding:0px 0px 0px 8px;">' . __( 'WP Roles', 'ultimate-member' ) . '</div>
                  </div>';

            $time_format = get_option( 'time_format' );

            foreach( $log['time'] as $key => $timestamp ) {

                echo '<div style="display: table-row;">
                        <div style="display: table-cell;" title="Seconds ' . esc_html( date_i18n(  's', $timestamp )) . '">' . esc_html( date_i18n(  $time_format, $timestamp )) . '</div>';

                foreach( $log['data'][$key] as $item ) {

                    if( is_array( $item )) {

                        $line  = '<div style="display: table-row;">
                                     <div style="display: table-cell;" title="Nonce Action for User ID ' . esc_html( $item['uid'] ) . '">' . esc_html( $item['action'] )  . '</div>
                                     <div style="display: table-cell; padding:0px 0px 0px 8px;" title="Session token ' . esc_html( $item['token'] ) . ' Tick ' . esc_html( $item['tick'] ) . '">' . esc_html( $item['nonce'] )  . '</div>
                                  </div>';

                        echo '<div style="display: table-row;">
                                <div style="display: table-cell; padding:0px 0px 0px 8px;">' . $line . '</div>
                              </div>';

                    } else {

                        if( strpos( $item, 'Bootstrap' ) > 0 ) $item = 'WP Bootstrap';
                        
                        echo '<div style="display: table-cell; padding:0px 0px 0px 8px;">' . esc_html( $item ) . '</div>';
                    }
                }
?>
                </div>
<?php
            }
        } else echo '<div>' . __( 'No Posts', 'ultimate-member' ) . '</div>';
    } else echo '<div>' . __( 'This is not possible for security reasons.', 'ultimate-member' ) . '</div>';

    $output = ob_get_contents();
    ob_end_clean();

    return $output;
}

function um_settings_structure_misc_redirect_log( $settings_structure ) {

    $settings_structure['misc']['fields'][] = array( 'id'      => 'redirect_log_user_id',
                                                     'type'    => 'text',
                                                     'label'   => __( "Redirect Login/Nonce Log User ID's", 'ultimate-member' ),
                                                     'tooltip' => __( "Enter the comma separated User ID's as integer numbers", 'ultimate-member' ),
                                                     'size'    => 'short' );

    $settings_structure['misc']['fields'][] = array( 'id'      => 'redirect_log_max_items',
                                                     'type'    => 'text',
                                                     'label'   => __( 'Redirect Login/Nonce Log max number of log entries', 'ultimate-member' ),
                                                     'tooltip' => __( 'Enter the number as a single integer number (typical values between 20 and 100)', 'ultimate-member' ),
                                                     'size'    => 'short' );                                                 

    return $settings_structure;
}
