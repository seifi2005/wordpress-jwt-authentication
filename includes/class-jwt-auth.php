<?php
defined('ABSPATH') || exit;

require_once plugin_dir_path(__FILE__) . '../vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWT_Auth {
    private static $secret_key = '99415d9cf09a882ee74ee7e27359b911550f721e47e397ee4c30f75cef50f3ae346c13bfea';
    private static $token_expiration = 600; // 24 ساعت

    public function generate_token($username) {
        $user = get_user_by('login', $username);
        if (!$user) {
            return [
                'status' => false,
                'message' => 'کاربر پیدا نشد.'
            ];
        }

        $issuedAt = time();
        $expire = $issuedAt + self::$token_expiration;

        $token_payload = [
            'iss' => get_site_url(),
            'iat' => $issuedAt,
            'exp' => $expire,
            'data' => [
                'user_id' => $user->ID,
                'username' => $user->user_login
            ],
            // 'kid' => 'main_key'
        ];

        date_default_timezone_set('Asia/Tehran');
        $gregorian_date = date('Y-m-d H:i:s', $expire);

        try {
            $jwt = JWT::encode($token_payload, self::$secret_key, 'HS256');
            return [
                'status' => true,
                'token' => $jwt,
                'expires_in' => $gregorian_date
            ];
        } catch (Exception $e) {
            return [
                'status' => false,
                'message' => 'خطا در ایجاد توکن: ' . $e->getMessage()
            ];
        }
    }

    public function handle_token_request() {
        $data = json_decode(file_get_contents('php://input'), true);

        if (empty($data['username']) || empty($data['password'])) {
            return new WP_REST_Response([
                'status' => false,
                'message' => 'نام کاربری و رمز عبور الزامی است.'
            ], 400);
        }

        $username = sanitize_text_field($data['username']);
        $password = sanitize_text_field($data['password']);

        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            return new WP_REST_Response([
                'status' => false,
                'message' => 'نام کاربری یا رمز عبور اشتباه است.'
            ], 401);
        }

        $token_response = $this->generate_token($username);
        return new WP_REST_Response($token_response, 200);
    }

    public function decode_token($request) {

        $headers = getallheaders();

        $header_token = explode(' ', $headers['Authorization']);
        $token = $header_token[1];
        if (empty($token)) {
            return [
                'status' => false,
                'message' => 'توکن ارائه نشده است.'
            ];
        }
        try {
            $decoded = JWT::decode($token, new Key(self::$secret_key, 'HS256'));
            date_default_timezone_set('Asia/Tehran');
            $current_time = time();
            $time_remaining = $decoded->exp - $current_time;
            if ($time_remaining > 0) {
                $days = floor($time_remaining / 86400);
                $hours = floor(($time_remaining % 86400) / 3600);
                $minutes = floor(($time_remaining % 3600) / 60);
                $seconds = $time_remaining % 60;
                $time_remaining_formatted = sprintf(
                    '%d روز، %d ساعت، %d دقیقه و %d ثانیه',
                    $days, $hours, $minutes, $seconds
                );
            } else {
                $time_remaining_formatted = 'منقضی شده';
            }
            return [
                'status' => true,
                'user_id' => $decoded->data->user_id,
                'username' => $decoded->data->username,
                'expires' => date('Y-m-d H:i:s', $decoded->exp),
                'time_remaining' => $time_remaining_formatted
            ];
        } catch (Exception $e) {
            return [
                'status' => false,
                'message' => 'توکن نامعتبر است. خطا: ' . $e->getMessage()
            ];
        }
    }



    public function register_routes() {
        register_rest_route('jwt-auth/v1', '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_token_request'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('jwt-auth/v1', '/debug', [
            'methods' => 'GET',
            'callback' => [$this, 'decode_token'],
            'permission_callback' => '__return_true'
        ]);
    }
}
