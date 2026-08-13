<?php
/**
 * Fake plugin entry point for honeypot
 */
require_once __DIR__ . '/../../../logger.php';
$log = new HoneypotLogger();
$log->log('wp-plugins.access', [
    'plugin' => basename(__DIR__),
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
]);
header('HTTP/1.0 404 Not Found');
echo '<h1>Not Found</h1><p>The requested URL was not found on this server.</p>';
