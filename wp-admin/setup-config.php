<?php
/**
 * JesterTrap WP - Fake wp-admin/setup-config.php
 * Simula el instalador de WordPress - captura intentos de reconfiguración
 */
require_once __DIR__ . '/../logger.php';

$log = new HoneypotLogger();

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('wp-admin.setup-config', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'step' => $_GET['step'] ?? '0',
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $ua,
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $log->log('wp-admin.setup-config.post', [
        'db_host' => $_POST['dbname'] ?? '',
        'uname' => $_POST['uname'] ?? '',
        'pwd' => $_POST['pwd'] ?? '',
        'dbhost' => $_POST['dbhost'] ?? '',
        'prefix' => $_POST['prefix'] ?? '',
        'ua' => $ua,
    ]);
}

header('Content-Type: text/html; charset=UTF-8');
$step = $_GET['step'] ?? '0';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Setup Configuration File &lsaquo; WordPress</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f0f0f1; color: #333; max-width: 700px; margin: 40px auto; padding: 20px; }
h1 { color: #2271b1; }
.form-table th { text-align: right; padding: 10px; }
.form-table td { padding: 10px; }
input { padding: 8px; border: 1px solid #8c8f94; border-radius: 4px; }
.button { background: #2271b1; color: #fff; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
</style>
</head>
<body>
<h1>WordPress › Setup Configuration File</h1>
<?php if ($step === '0'): ?>
<p>Below you should enter your database connection details. If you're not sure about these, contact your host.</p>
<form method="post" action="?step=1">
<table class="form-table">
<tr><th>Database Name</th><td><input name="dbname" type="text" size="25" value="wordpress"></td></tr>
<tr><th>Username</th><td><input name="uname" type="text" size="25" value="root"></td></tr>
<tr><th>Password</th><td><input name="pwd" type="password" size="25" value=""></td></tr>
<tr><th>Database Host</th><td><input name="dbhost" type="text" size="25" value="localhost"></td></tr>
<tr><th>Table Prefix</th><td><input name="prefix" type="text" size="25" value="wp_"></td></tr>
</table>
<p class="step"><input type="submit" class="button" value="Submit"></p>
</form>
<?php else: ?>
<p>Sorry, but the database connection information you provided are incorrect. Please check and try again.</p>
<p><a href="?step=0">Try again</a></p>
<?php endif; ?>
</body>
</html>