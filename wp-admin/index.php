<?php
/**
 * JesterTrap WP - Fake wp-admin index
 * Requires login - redirects to wp-login.php
 */
require_once '/var/www/wp-honeypot/logger.php';
$log = new HoneypotLogger();

$log->log('wp-admin.visit', [
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
]);

// Redirect to login
header('Location: /wp-login.php?redirect_to=' . urlencode($_SERVER['REQUEST_URI'] ?? '/wp-admin/'));
exit;