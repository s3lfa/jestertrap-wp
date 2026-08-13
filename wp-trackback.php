<?php
/**
 * JesterTrap WP - Fake wp-trackback.php
 * Captura ataques trackback/pingback
 */
require_once __DIR__ . '/logger.php';

$log = new HoneypotLogger();

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('wp-trackback.visit', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $ua,
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'] ?? '';
    $excerpt = $_POST['excerpt'] ?? '';
    $url = $_POST['url'] ?? '';
    $blogName = $_POST['blog_name'] ?? '';
    $tbID = $_POST['tb_id'] ?? '';

    $log->log('wp-trackback.attempt', [
        'title' => mb_substr($title, 0, 500),
        'excerpt' => mb_substr($excerpt, 0, 500),
        'url' => mb_substr($url, 0, 500),
        'blog_name' => mb_substr($blogName, 0, 500),
        'tb_id' => $tbID,
        'ua' => $ua,
    ]);

    // Responder como WP: trackback registrado
    echo '<?xml version="1.0" encoding="UTF-8"?>
<response>
<error>0</error>
<message>Trackback registered.</message>
</response>';
    exit;
}

// GET: mostrar página de trackback
header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html><head><title>Trackback</title></head>
<body><p>Trackback URL for this post.</p></body></html>
<?php
exit;