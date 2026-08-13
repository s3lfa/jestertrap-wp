<?php
/**
 * JesterTrap WP - Fake wp-admin/admin-ajax.php
 * Uno de los endpoints más atacados de WordPress
 * Captura peticiones AJAX maliciosas, intentos de explotación de plugins
 */
require_once __DIR__ . '/../logger.php';

$log = new HoneypotLogger();

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$action = $_REQUEST['action'] ?? '';

$log->log('wp-admin.ajax', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'action' => $action,
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $ua,
    'post_data' => mb_substr(json_encode($_POST), 0, 2000),
]);

// Responder según la acción - simular respuestas conocidas
switch ($action) {
    case 'heartbeat':
        // WP heartbeat responde con timestamp
        header('Content-Type: application/json');
        echo json_encode(['wp-refresh-post-nonces' => ['post_id' => 1, 'nonce' => substr(md5(time()), 0, 10)]]);
        break;

    case 'fetch-list':
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'data' => []]);
        break;

    default:
        // Respuesta genérica die(-1) como WP real
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Robots-Tag: noindex');
        echo '0';
        break;
}