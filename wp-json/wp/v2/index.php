<?php
/**
 * JesterTrap WP - REST API v2 Enhanced
 * Simula la REST API real de WordPress con soporte para SQLi
 * /wp-json/wp/v2/posts, /wp/v2/users, /wp/v2/comments, /wp/v2/pages
 */
require_once '/var/www/wp-honeypot/logger.php';
require_once '/var/www/wp-honeypot/sqli-responder.php';

$log = new HoneypotLogger();
$uri = $_SERVER['REQUEST_URI'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('rest-api.request', [
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
        'endpoint' => 'rest-api',
    ]);
    $sqliPayload = $sqliAttacks[0]['value'];
    $responder = new SQLiResponder();
    // Para REST API, devolver error en JSON
    header('Content-Type: application/json; charset=UTF-8');
    http_response_code(500);
    echo json_encode([
        'code' => 'rest_database_error',
        'message' => "WordPress database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL (8.0.36) server version for the right syntax to use near '" . substr($sqliPayload, 0, 60) . "' at line 1",
        'data' => ['status' => 500],
    ]);
    exit;
}

// Parsear la ruta REST
$path = parse_url($uri, PHP_URL_PATH);
// /wp-json/wp/v2/posts, /wp-json/wp/v2/users/1, etc.

// Datos fake
$posts = [
    ['id' => 1, 'date' => '2024-12-25T10:00:00', 'date_gmt' => '2024-12-25T10:00:00', 'modified' => '2024-12-25T10:00:00', 'title' => ['rendered' => 'Hello world!'], 'content' => ['rendered' => 'Welcome to WordPress. This is your first post.'], 'excerpt' => ['rendered' => 'Welcome to WordPress...'], 'author' => 1, 'slug' => 'hello-world', 'status' => 'publish', 'type' => 'post', 'link' => 'http://myblog.com/2024/12/hello-world/', 'categories' => [1], 'tags' => [], '_links' => ['self' => [['href' => 'http://myblog.com/wp-json/wp/v2/posts/1']], 'collection' => [['href' => 'http://myblog.com/wp-json/wp/v2/posts']], 'author' => [['embeddable' => true, 'href' => 'http://myblog.com/wp-json/wp/v2/users/1']]]],
    ['id' => 2, 'date' => '2024-12-26T11:00:00', 'date_gmt' => '2024-12-26T11:00:00', 'modified' => '2024-12-26T11:00:00', 'title' => ['rendered' => 'My Second Post'], 'content' => ['rendered' => 'Lorem ipsum dolor sit amet.'], 'excerpt' => ['rendered' => 'Lorem ipsum...'], 'author' => 1, 'slug' => 'my-second-post', 'status' => 'publish', 'type' => 'post', 'link' => 'http://myblog.com/2024/12/my-second-post/', 'categories' => [1], 'tags' => []],
    ['id' => 3, 'date' => '2024-12-27T14:00:00', 'date_gmt' => '2024-12-27T14:00:00', 'modified' => '2024-12-27T14:00:00', 'title' => ['rendered' => 'Another Interesting Post'], 'content' => ['rendered' => 'Sed do eiusmod tempor.'], 'excerpt' => ['rendered' => 'Sed do eiusmod...'], 'author' => 2, 'slug' => 'another-interesting-post', 'status' => 'publish', 'type' => 'post', 'link' => 'http://myblog.com/2024/12/another-interesting-post/', 'categories' => [2], 'tags' => []],
    ['id' => 4, 'date' => '2025-01-10T09:00:00', 'date_gmt' => '2025-01-10T09:00:00', 'modified' => '2025-01-10T09:00:00', 'title' => ['rendered' => '10 Tips for Better Blogging'], 'content' => ['rendered' => 'Here are some practical tips.'], 'excerpt' => ['rendered' => 'Practical tips...'], 'author' => 3, 'slug' => '10-tips-for-better-blogging', 'status' => 'publish', 'type' => 'post', 'link' => 'http://myblog.com/2025/01/10-tips-for-better-blogging/', 'categories' => [3], 'tags' => []],
    ['id' => 5, 'date' => '2025-02-15T16:30:00', 'date_gmt' => '2025-02-15T16:30:00', 'modified' => '2025-02-15T16:30:00', 'title' => ['rendered' => 'The Future of Web Design'], 'content' => ['rendered' => 'Exploring upcoming trends.'], 'excerpt' => ['rendered' => 'Exploring trends...'], 'author' => 1, 'slug' => 'the-future-of-web-design', 'status' => 'publish', 'type' => 'post', 'link' => 'http://myblog.com/2025/02/the-future-of-web-design/', 'categories' => [2], 'tags' => []],
];

$users = [
    ['id' => 1, 'name' => 'admin', 'slug' => 'admin', 'link' => 'http://myblog.com/author/admin/', 'description' => 'Site administrator', 'registered_date' => '2024-12-25T10:00:00', 'roles' => ['administrator'], 'url' => ''],
    ['id' => 2, 'name' => 'editor', 'slug' => 'editor', 'link' => 'http://myblog.com/author/editor/', 'description' => 'Content editor', 'registered_date' => '2024-12-26T12:00:00', 'roles' => ['editor'], 'url' => ''],
    ['id' => 3, 'name' => 'John Writer', 'slug' => 'john-writer', 'link' => 'http://myblog.com/author/john-writer/', 'description' => 'Author and blogger', 'registered_date' => '2025-01-05T09:30:00', 'roles' => ['author'], 'url' => ''],
];

$comments = [
    ['id' => 1, 'post' => 1, 'author' => 'Mr WordPress', 'author_name' => 'Mr WordPress', 'author_email' => '', 'content' => ['rendered' => 'Hi, this is a comment.'], 'date' => '2024-12-25T10:00:00', 'status' => 'approved', 'type' => 'comment'],
    ['id' => 2, 'post' => 2, 'author' => 'Sarah', 'author_name' => 'Sarah', 'author_email' => 'sarah@example.com', 'content' => ['rendered' => 'Great post!'], 'date' => '2024-12-26T15:00:00', 'status' => 'approved', 'type' => 'comment'],
];

$pages = [
    ['id' => 2, 'date' => '2024-12-25T10:00:00', 'title' => ['rendered' => 'About'], 'content' => ['rendered' => 'This is the about page.'], 'slug' => 'about', 'status' => 'publish', 'type' => 'page', 'link' => 'http://myblog.com/about/'],
    ['id' => 3, 'date' => '2024-12-25T10:00:00', 'title' => ['rendered' => 'Contact'], 'content' => ['rendered' => 'Contact us at admin@myblog.com'], 'slug' => 'contact', 'status' => 'publish', 'type' => 'page', 'link' => 'http://myblog.com/contact/'],
];

$categories = [
    ['id' => 1, 'name' => 'Uncategorized', 'slug' => 'uncategorized', 'link' => 'http://myblog.com/category/uncategorized/', 'count' => 2],
    ['id' => 2, 'name' => 'News', 'slug' => 'news', 'link' => 'http://myblog.com/category/news/', 'count' => 2],
    ['id' => 3, 'name' => 'Tips', 'slug' => 'tips', 'link' => 'http://myblog.com/category/tips/', 'count' => 1],
];

header('Content-Type: application/json; charset=UTF-8');
header('X-Robots-Tag: noindex');

// Rutar según el path
if (preg_match('#/wp-json/wp/v2/?$#', $path) || preg_match('#/wp-json/?$#', $path)) {
    // Root de la API
    echo json_encode([
        'name' => 'My Blog',
        'description' => 'Just another WordPress site',
        'url' => 'http://' . ($_SERVER['HTTP_HOST'] ?? 'myblog.com'),
        'namespaces' => ['core/v2', 'oembed/1.0', 'wp/v2', 'wc/v3', 'contact-form-7/v1'],
        'routes' => [
            '/wp/v2/posts' => ['methods' => ['GET', 'POST'], 'endpoints' => [['methods' => ['GET']], ['methods' => ['POST']]]],
            '/wp/v2/posts/(?P<id>[\d]+)' => ['methods' => ['GET', 'POST', 'PUT', 'DELETE'], 'endpoints' => [['methods' => ['GET']]]],
            '/wp/v2/users' => ['methods' => ['GET', 'POST'], 'endpoints' => [['methods' => ['GET']], ['methods' => ['POST']]]],
            '/wp/v2/users/(?P<id>[\d]+)' => ['methods' => ['GET'], 'endpoints' => [['methods' => ['GET']]]],
            '/wp/v2/comments' => ['methods' => ['GET', 'POST'], 'endpoints' => [['methods' => ['GET']], ['methods' => ['POST']]]],
            '/wp/v2/pages' => ['methods' => ['GET'], 'endpoints' => [['methods' => ['GET']]]],
            '/wp/v2/categories' => ['methods' => ['GET'], 'endpoints' => [['methods' => ['GET']]]],
            '/wc/v3/products' => ['methods' => ['GET'], 'endpoints' => [['methods' => ['GET']]]],
        ],
        '_links' => ['help' => [['href' => 'https://developer.wordpress.org/rest-api/']]],
    ], JSON_PRETTY_PRINT);
    exit;
}

// /wp/v2/posts
if (preg_match('#/wp-json/wp/v2/posts/?$#', $path)) {
    // Aplicar filtros fake
    $result = $posts;
    $search = $_GET['search'] ?? '';
    if ($search) {
        $result = array_filter($posts, fn($p) => stripos($p['title']['rendered'], $search) !== false);
    }
    echo json_encode(array_values($result));
    exit;
}

// /wp/v2/posts/{id}
if (preg_match('#/wp-json/wp/v2/posts/(\d+)#', $path, $m)) {
    $id = (int)$m[1];
    $found = array_filter($posts, fn($p) => $p['id'] === $id);
    if (!empty($found)) {
        echo json_encode(array_values($found)[0]);
    } else {
        http_response_code(404);
        echo json_encode(['code' => 'rest_post_invalid_id', 'message' => 'Invalid post ID.', 'data' => ['status' => 404]]);
    }
    exit;
}

// /wp/v2/users
if (preg_match('#/wp-json/wp/v2/users/?$#', $path)) {
    echo json_encode($users);
    exit;
}

// /wp/v2/users/{id}
if (preg_match('#/wp-json/wp/v2/users/(\d+)#', $path, $m)) {
    $id = (int)$m[1];
    $found = array_filter($users, fn($u) => $u['id'] === $id);
    if (!empty($found)) {
        echo json_encode(array_values($found)[0]);
    } else {
        http_response_code(404);
        echo json_encode(['code' => 'rest_user_invalid_id', 'message' => 'Invalid user ID.', 'data' => ['status' => 404]]);
    }
    exit;
}

// /wp/v2/comments
if (preg_match('#/wp-json/wp/v2/comments/?$#', $path)) {
    echo json_encode($comments);
    exit;
}

// /wp/v2/pages
if (preg_match('#/wp-json/wp/v2/pages/?$#', $path)) {
    echo json_encode($pages);
    exit;
}

// /wp/v2/categories
if (preg_match('#/wp-json/wp/v2/categories/?$#', $path)) {
    echo json_encode($categories);
    exit;
}

// WooCommerce fake
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
echo json_encode(['code' => 'rest_no_route', 'message' => 'No route was found matching the URL and request method.', 'data' => ['status' => 404]]);