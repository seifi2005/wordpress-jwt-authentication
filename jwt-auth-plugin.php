<?php
/**
 * Plugin Name: JWT Authentication Plugin
 * Description: A simple JWT authentication plugin for WordPress.
 * Version: 1.0
 * Author: محمد سیفی
 */

defined('ABSPATH') || exit;

// شامل کردن فایل کلاس اصلی افزونه
require_once plugin_dir_path(__FILE__) . 'includes/class-jwt-auth.php';

// مقداردهی اولیه افزونه
function jwt_auth_plugin_init() {
    $jwt_auth = new JWT_Auth();
    add_action('rest_api_init', [$jwt_auth, 'register_routes']);
}


add_action('plugins_loaded', 'jwt_auth_plugin_init');
