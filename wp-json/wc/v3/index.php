<?php
/**
 * JesterTrap WP - WooCommerce REST API v3 fake
 * /wp-json/wc/v3/products
 */
require_once '/var/www/wp-honeypot/logger.php';
require_once '/var/www/wp-honeypot/sqli-responder.php';

$log = new HoneypotLogger();
$uri = $_SERVER['REQUEST_URI'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('rest-api.wc', [
    'uri' => $uri,
    'method' => $method,
    'ua' => $ua,
]);

// Detectar SQLi
$detector = new AttackDetector();
$headers = ['user_agent' => $ua, 'referer' => $_SERVER['HTTP_REFERER'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? ''];
$body = file_get_contents('php://input') ?: null;
$attacks = $detector->detect($_SERVER['REMOTE_ADDR'] ?? '', $uri, $method, $headers, $body);
$sqliAttacks = array_filter($attacks, fn($a) => $a['type'] === 'sqli');

if (!empty($sqliAttacks)) {
    $log->log('sqli.detected', [
        'uri' => $uri,
        'payload' => mb_substr($uri . ($body ?? ''), 0, 2000),
        'attacks' => $sqliAttacks,
        'endpoint' => 'wc-api',
    ]);
    $sqliPayload = $sqliAttacks[0]['value'];
    header('Content-Type: application/json; charset=UTF-8');
    http_response_code(500);
    echo json_encode([
        'code' => 'woocommerce_rest_database_error',
        'message' => "WordPress database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL (8.0.36) server version for the right syntax to use near '" . substr($sqliPayload, 0, 60) . "' at line 1",
        'data' => ['status' => 500],
    ]);
    exit;
}

$path = parse_url($uri, PHP_URL_PATH);
header('Content-Type: application/json; charset=UTF-8');
header('X-Robots-Tag: noindex');

if (preg_match('#/wp-json/wc/v3/products/?$#', $path)) {
    echo json_encode([
        ['id' => 1, 'name' => 'Premium Theme', 'slug' => 'premium-theme', 'price' => '49.99', 'regular_price' => '59.99', 'sale_price' => '49.99', 'status' => 'publish', 'type' => 'simple', 'stock_status' => 'instock', 'permalink' => 'http://myblog.com/product/premium-theme/'],
        ['id' => 2, 'name' => 'SEO Plugin Pro', 'slug' => 'seo-plugin-pro', 'price' => '29.99', 'regular_price' => '29.99', 'status' => 'publish', 'type' => 'simple', 'stock_status' => 'instock', 'permalink' => 'http://myblog.com/product/seo-plugin-pro/'],
        ['id' => 3, 'name' => 'Security Bundle', 'slug' => 'security-bundle', 'price' => '99.00', 'regular_price' => '149.00', 'sale_price' => '99.00', 'status' => 'publish', 'type' => 'simple', 'stock_status' => 'instock', 'permalink' => 'http://myblog.com/product/security-bundle/'],
    ]);
    exit;
}

// Default 404
http_response_code(404);
echo json_encode(['code' => 'woocommerce_rest_no_route', 'message' => 'No route was found matching the URL and request method.', 'data' => ['status' => 404]]);
