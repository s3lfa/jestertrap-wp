<?php
/**
 * JesterTrap WP - Fake Plugin Endpoints
 * Simula plugins vulnerables conocidos para cazar exploits específicos
 * - Contact Form 7: /wp-json/contact-form-7/v1/contact-forms
 * - Duplicator: /wp-content/plugins/duplicator/ + installer endpoint
 */
require_once __DIR__ . '/../../logger.php';
require_once __DIR__ . '/../../sqli-responder.php';

$log = new HoneypotLogger();
$uri = $_SERVER['REQUEST_URI'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('plugin.endpoint', ['uri' => $uri, 'ua' => $ua]);

// Detectar SQLi
$detector = new AttackDetector();
$headers = ['user_agent' => $ua, 'referer' => $_SERVER['HTTP_REFERER'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? ''];
$body = file_get_contents('php://input') ?: null;
$attacks = $detector->detect($_SERVER['REMOTE_ADDR'] ?? '', $uri, $_SERVER['REQUEST_METHOD'] ?? 'GET', $headers, $body);

if (!empty($attacks)) {
    $log->log('plugin.attack', [
        'uri' => $uri,
        'payload' => mb_substr($uri . ($body ?? ''), 0, 2000),
        'attacks' => $attacks,
    ]);

    // Si es SQLi, responder con error SQL
    $sqliAttacks = array_filter($attacks, fn($a) => $a['type'] === 'sqli');
    if (!empty($sqliAttacks)) {
        $responder = new SQLiResponder();
        $responder->respond($sqliAttacks[0]['value'], $uri);
        exit;
    }
}

// Contact Form 7 endpoint
if (preg_match('#/wp-json/contact-form-7/v1#', $uri)) {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        ['id' => 1, 'title' => 'Contact form 1', 'slug' => 'contact-form-1', 'short_code' => '[contact-form-7 id="1" title="Contact form 1"]'],
        ['id' => 2, 'title' => 'Newsletter signup', 'slug' => 'newsletter-signup', 'short_code' => '[contact-form-7 id="2" title="Newsletter signup"]'],
    ]);
    exit;
}

// Duplicator installer (CVE-2024-xxxx)
if (preg_match('#/wp-content/plugins/duplicator/installer#', $uri)) {
    // Simular que el installer existe y responde
    header('Content-Type: text/html; charset=UTF-8');
    echo '<html><body><h1>Duplicator Installer</h1><p>Installer file detected. Archive: wp-package-2024.zip</p></body></html>';
    exit;
}

// WPForms
if (preg_match('#/wp-json/wpforms/v1#', $uri)) {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['forms' => [['id' => 1, 'title' => 'Contact Form', 'fields' => 3]]]);
    exit;
}

// Default
http_response_code(404);
echo "Plugin endpoint not found.";