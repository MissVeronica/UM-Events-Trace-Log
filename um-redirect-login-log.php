<?php
/**
 * Plugin Name:     Ultimate Member - Redirect Login Log
 * Description:     Extension to Ultimate Member for logging all redirects during login.
 * Version:         1.0.0
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


add_action( 'um_user_login', 'um_user_login_trace', 9 );
add_filter( 'x_redirect_by', 'wp_redirect_login_log', 10, 3 );
add_shortcode( 'redirect_login_log', 'redirect_login_log_shortcode' );
remove_action( 'um_user_login', 'um_user_login', 10 );

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
        my_um_redirect_login_log( 'Priority redirect', $args['redirect_to'] );
        exit( wp_safe_redirect( $args['redirect_to'] ) );
	}

	// Role redirect
	$after_login = um_user( 'after_login' );
	if ( empty( $after_login ) ) {
        my_um_redirect_login_log( 'Role redirect', um_user_profile_url() );
		exit( wp_redirect( um_user_profile_url() ) );
	}

	switch ( $after_login ) {

		case 'redirect_admin':
            my_um_redirect_login_log( 'redirect_admin', admin_url() );
            exit( wp_redirect( admin_url() ) );
			break;

		case 'redirect_url':
            my_um_redirect_login_log( 'redirect_url filter in', um_user( 'login_redirect_url' ) );
			$redirect_url = apply_filters( 'um_login_redirect_url', um_user( 'login_redirect_url' ), um_user( 'ID' ) );
			my_um_redirect_login_log( 'redirect_url filter out', $redirect_url );
            exit( wp_redirect( $redirect_url ) );
			break;

		case 'refresh':
            my_um_redirect_login_log( 'refresh', UM()->permalinks()->get_current_url() );
            exit( wp_redirect( UM()->permalinks()->get_current_url() ) );
			break;

		case 'redirect_profile':
		default:
            my_um_redirect_login_log( $after_login, um_user_profile_url() );
            exit( wp_redirect( um_user_profile_url() ) );
			break;

	}
}

function wp_redirect_login_log( $x_redirect_by, $status, $location ) {

    my_um_redirect_login_log( 'wp_redirect', $location );

    return $x_redirect_by;
}

function my_um_redirect_login_log( $status, $redirect ) {

    $log = get_option( 'um_redirect_login_log' );
    if( empty( $log )) $log = array();

    if( isset($_GET['provider'] )) $provider = $_GET['provider']; else $provider = '';
    $log[] = array( current_time( 'timestamp' ), 
                    um_user( 'ID' ), 
                    um_user('user_login' ), 
                    $status, 
                    $redirect, 
                    $provider,                     
                    UM()->roles()->get_priority_user_role( um_user( 'ID' ) ),
                    um_user('wp_roles' ),
                 );

    if( count( $log ) > 30 ) array_shift( $log );
    update_option( 'um_redirect_login_log', $log, false );
}

function redirect_login_log_shortcode( $atts ) {

    if( current_user_can( 'administrator' )) {

        $log = get_option( 'um_redirect_login_log' );

        ob_start();
        echo '<h4>' . __( 'Redirect Login Log in reverse order', 'ultimate-member' ) . '</h4>';
        
        if( !empty( $log )) {

            $log = array_reverse( $log );

            echo '<div style="display: table-row;">';
            echo '<div style="display: table-cell;">' . __( 'Date', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'ID', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'User', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'Status', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'Redirect', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'Provider', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'Priority Role', 'ultimate-member' ) . '</div>';
            echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . __( 'wp_roles', 'ultimate-member' ) . '</div>';
            echo '</div>';

            $time_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

            foreach( $log as $items ) {

                echo '<div style="display: table-row;">';
                echo '<div style="display: table-cell;">';
                echo date_i18n(  $time_format, $items[0] ) . '</div>';
                unset( $items[0] );
                foreach( $items as $item ) {
                    echo '<div style="display: table-cell; padding:0px 0px 0px 10px;">' . $item . '</div>';
                }
                echo '</div>';
            }
        } else echo '<div>' . __( 'No Posts', 'ultimate-member' ) . '</div>';
    } else echo '<div>' . __( 'This is not possible for security reasons.', 'ultimate-member' ) . '</div>';

    $output = ob_get_contents();
    ob_end_clean();
    
    return $output;
}
