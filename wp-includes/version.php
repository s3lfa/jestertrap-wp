<?php
/**
 * JesterTrap WP - Fake wp-includes/version.php
 * Expone la versión de WordPress para fingerprinting
 * Los scanners buscan este archivo para determinar la versión exacta
 */
$wp_version = '6.5.2';
$wp_db_version = 57950;
$tinymce_version = '7.2.0';
$required_php_version = '7.2.24';
$required_mysql_version = '10.0';

// No loguear esto - es solo para fingerprinting
// Pero logueamos la visita via el index general
header('Content-Type: text/plain');
echo "<?php\n";
echo "/**\n * The WordPress version string\n */\n";
echo "\$wp_version = '$wp_version';\n";
echo "\$wp_db_version = $wp_db_version;\n";
echo "\$tinymce_version = '$tinymce_version';\n";
echo "\$required_php_version = '$required_php_version';\n";
echo "\$required_mysql_version = '$required_mysql_version';\n";