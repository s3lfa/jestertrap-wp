<?php
/**
 * JesterTrap WP - Fake wp-content/plugins/index.php
 * Simula enumeración de plugins - loguea qué plugins buscan los atacantes
 */
require_once __DIR__ . '/../../logger.php';

$log = new HoneypotLogger();

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$uri = $_SERVER['REQUEST_URI'] ?? '';

$log->log('wp-plugins.enum', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'uri' => $uri,
    'ua' => $ua,
]);

// Extraer nombre del plugin de la URI
if (preg_match('#/wp-content/plugins/([^/]+)#', $uri, $m)) {
    $plugin = $m[1];
    $log->log('wp-plugins.search', [
        'plugin_name' => $plugin,
        'uri' => $uri,
        'ua' => $ua,
    ]);
}

// Listar algunos plugins como si existieran (directory listing fake)
header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html><head><title>Index of /wp-content/plugins/</title>
<style>body{font-family:monospace;} a{text-decoration:none;} h1{font-size:1.2em;}</style>
</head><body>
<h1>Index of /wp-content/plugins/</h1>
<ul>
<li><a href="../">Parent Directory</a></li>
<li><a href="akismet/"> akismet/</a></li>
<li><a href="hello.php"> hello.php</a></li>
<li><a href="yoast-seo/"> yoast-seo/</a></li>
<li><a href="elementor/"> elementor/</a></li>
<li><a href="contact-form-7/"> contact-form-7/</a></li>
<li><a href="wpforms-lite/"> wpforms-lite/</a></li>
<li><a href="all-in-one-seo-pack/"> all-in-one-seo-pack/</a></li>
<li><a href="wordfence/"> wordfence/</a></li>
<li><a href="wpdiscuz/"> wpdiscuz/</a></li>
<li><a href="woocommerce/"> woocommerce/</a></li>
<li><a href="duplicator/"> duplicator/</a></li>
<li><a href="wpfilemanager/"> wpfilemanager/</a></li>
</ul>
</body></html>