<?php
/**
 * JesterTrap WP - Fake wp-login.php
 * Captures login attempts (brute force, credential stuffing)
 */
require_once __DIR__ . '/logger.php';

$log = new HoneypotLogger();

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$uri = $_SERVER['REQUEST_URI'] ?? '';

// Log the visit to wp-login
$log->log('wp-login.visit', [
    'uri' => $uri,
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'ua' => $ua
]);

// Handle POST login attempts
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['log'] ?? $_POST['username'] ?? '';
    $pass = $_POST['pwd'] ?? $_POST['password'] ?? '';
    $redirect = $_POST['redirect_to'] ?? '';

    $log->log('wp-login.attempt', [
        'username' => $user,
        'password' => $pass,
        'redirect_to' => $redirect,
        'ua' => $ua
    ]);

    // Always respond with "incorrect password" to keep them trying
    $error_msg = 'ERROR: The password you entered for the username ' . htmlspecialchars($user) . ' is incorrect.';
    show_login_form($error_msg);
    exit;
}

// GET request - show login form
$action = $_GET['action'] ?? '';
if ($action === 'logout') {
    $log->log('wp-login.logout', ['ua' => $ua]);
    show_login_form('', 'You are now logged out.');
    exit;
}
if ($action === 'lostpassword') {
    $log->log('wp-login.lostpassword', ['ua' => $ua]);
    show_lostpassword_form();
    exit;
}

show_login_form();
exit;

function show_login_form($error = '', $info = '') {
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Powered-By: PHP/8.3.6');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress 6.5.2">
<title>Log In &lsaquo; My Blog &#8212; WordPress</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css" type="text/css" media="all">
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" type="text/css" media="all">
<script src="/wp-includes/js/jquery/jquery.min.js" id="jquery-core-js"></script>
</head>
<body class="login login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<?php if ($error): ?>
<div id="login_error"><?php echo $error; ?></div>
<?php endif; ?>
<?php if ($info): ?>
<p class="message"><?php echo $info; ?></p>
<?php endif; ?>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="none" autocomplete="username" required="required">
</p>
<p>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" required="required">
</p>
<p class="forgetmenot">
<label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label>
</p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</p>
</form>
<p id="nav">
<a href="/wp-login.php?action=lostpassword">Lost your password?</a>
</p>
<p id="backtoblog">
<a href="/">&larr; Go to My Blog</a>
</p>
</div>
<script>document.getElementById('user_login').focus();</script>
</body>
</html>
<?php
}

function show_lostpassword_form() {
    header('Content-Type: text/html; charset=UTF-8');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lost Password &lsaquo; My Blog &#8212; WordPress</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css" type="text/css" media="all">
</head>
<body class="login login-action-lostpassword wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<p class="message">Please enter your username or email address. You will receive a link to create a new password via email.</p>
<form name="lostpasswordform" id="lostpasswordform" action="/wp-login.php?action=lostpassword" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="user_login" id="user_login" class="input" value="" size="20" autocapitalize="none" autocomplete="username">
</p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Get New Password">
</p>
</form>
<p id="nav">
<a href="/wp-login.php">Log in</a>
</p>
<p id="backtoblog">
<a href="/">&larr; Go to My Blog</a>
</p>
</div>
</body>
</html>
<?php
}