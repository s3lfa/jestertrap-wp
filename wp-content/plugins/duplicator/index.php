<?php
/**
 * JesterTrap WP - Duplicator plugin fake
 * Simula el plugin Duplicator con vulnerabilidad conocida
 */
require_once __DIR__ . '/../../logger.php';
$log = new HoneypotLogger();
$log->log('plugin.duplicator', ['uri' => $_SERVER['REQUEST_URI'] ?? '']);

// Simular installer.php (vulnerabilidad de Duplicator)
if (strpos($_SERVER['REQUEST_URI'] ?? '', 'installer.php') !== false) {
    header('Content-Type: text/html; charset=UTF-8');
    echo '<html><head><title>Duplicator Installer</title></head><body>';
    echo '<h1>Duplicator Installer v1.5.10</h1>';
    echo '<p>Package: wp-package-2024-12-25.zip</p>';
    echo '<p>Archive detected. Ready to extract.</p>';
    echo '<form method="post"><button type="submit" name="action" value="extract">Extract Package</button></form>';
    echo '</body></html>';
    exit;
}

// Default
http_response_code(404);
echo "404 Not Found";