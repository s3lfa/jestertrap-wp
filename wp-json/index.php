<?php
/**
 * JesterTrap WP - REST API Root
 * Responde en /wp-json/ con el discovery de la API
 */
require_once __DIR__ . '/../logger.php';
$log = new HoneypotLogger();
$log->log('rest-api.root', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);

header('Content-Type: application/json; charset=UTF-8');
echo json_encode([
    'name' => 'My Blog',
    'description' => 'Just another WordPress site',
    'url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com'),
    'home' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com'),
    'gmt_offset' => '0',
    'timezone_string' => 'UTC',
    'namespaces' => [
        'core/v2', 'oembed/1.0', 'wp/v2', 'wc/v3', 'contact-form-7/v1',
    ],
    'authentication' => [
        'oauth1' => [
            'request' => ['url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com') . '/wp-json/oauth1/request'],
            'authorize' => ['url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com') . '/wp-json/oauth1/authorize'],
            'access' => ['url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com') . '/wp-json/oauth1/access'],
        ],
        'wpApplication' => ['application_passwords_endpoint' => '/wp-json/wp/v2/users/me/application-passwords'],
    ],
    'routes' => [
        '/wp/v2' => [
            'methods' => ['GET'],
            'endpoints' => [['methods' => ['GET']]],
        ],
        '/wp/v2/posts' => [
            'methods' => ['GET', 'POST'],
            'endpoints' => [['methods' => ['GET']], ['methods' => ['POST']]],
        ],
        '/wp/v2/users' => [
            'methods' => ['GET'],
            'endpoints' => [['methods' => ['GET']]],
        ],
        '/wp/v2/comments' => [
            'methods' => ['GET', 'POST'],
            'endpoints' => [['methods' => ['GET']], ['methods' => ['POST']]],
        ],
        '/wp/v2/pages' => [
            'methods' => ['GET'],
            'endpoints' => [['methods' => ['GET']]],
        ],
        '/wp/v2/categories' => [
            'methods' => ['GET'],
            'endpoints' => [['methods' => ['GET']]],
        ],
        '/wc/v3/products' => [
            'methods' => ['GET'],
            'endpoints' => [['methods' => ['GET']]],
        ],
    ],
    '_links' => [
        'help' => [['href' => 'https://developer.wordpress.org/rest-api/']],
        'wp:items' => [['href' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com') . '/wp-json/wp/v2']],
        'curies' => [['name' => 'wp', 'href' => 'https://api.w.org/{rel}', 'templated' => true]],
    ],
], JSON_PRETTY_PRINT);