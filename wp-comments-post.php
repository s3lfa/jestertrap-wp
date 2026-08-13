<?php
/**
 * JesterTrap WP - Enhanced wp-comments-post.php
 * Captura spam, XSS stored, SQLi en campos de comentario
 */
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/sqli-responder.php';

$log = new HoneypotLogger();
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('wp-comments.visit', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $ua,
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $author = $_POST['author'] ?? '';
    $email = $_POST['email'] ?? '';
    $url = $_POST['url'] ?? '';
    $comment = $_POST['comment'] ?? '';
    $postID = $_POST['comment_post_ID'] ?? '';

    // Concatenar todos los campos para detectar ataques
    $allInputs = $author . ' ' . $email . ' ' . $url . ' ' . $comment;
    $detector = new AttackDetector();
    $headers = ['user_agent' => $ua, 'referer' => $_SERVER['HTTP_REFERER'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? ''];
    $attacks = $detector->detect($_SERVER['REMOTE_ADDR'] ?? '', '', 'POST', $headers, $allInputs);

    // Log con detalles del comentario
    $log->log('wp-comments.spam', [
        'author' => $author,
        'email' => $email,
        'url' => $url,
        'comment' => mb_substr($comment, 0, 2000),
        'post_id' => $postID,
        'ua' => $ua,
        'attacks' => $attacks ?: null,
    ]);

    // Si hay SQLi en los campos, responder con error de BD
    $sqliAttacks = array_filter($attacks, fn($a) => $a['type'] === 'sqli');
    if (!empty($sqliAttacks)) {
        $log->log('sqli.detected', [
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'payload' => mb_substr($allInputs, 0, 2000),
            'attacks' => $sqliAttacks,
            'endpoint' => 'comments',
            'fields' => ['author' => $author, 'email' => $email, 'comment' => $comment],
        ]);
        $responder = new SQLiResponder();
        $responder->generateError($sqliAttacks[0]['value']);
        exit;
    }

    // Si hay XSS, "aceptar" el comentario (stored XSS fake)
    $xssAttacks = array_filter($attacks, fn($a) => $a['type'] === 'xss');
    if (!empty($xssAttacks)) {
        $log->log('xss.stored', [
            'comment' => mb_substr($comment, 0, 1000),
            'author' => $author,
            'fields' => ['author' => $author, 'url' => $url, 'comment' => $comment],
        ]);
        // Responder como WP: comentario pendiente
        showCommentPending();
        exit;
    }

    // Comentario normal
    showCommentPending();
    exit;
}

// GET: redirigir al blog
header('Location: /');
exit;

function showCommentPending() {
    header('Content-Type: text/html; charset=UTF-8');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Comment &lsaquo; My Blog</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:600px;margin:80px auto;padding:20px;color:#333}
.comment-msg{background:#f0f0f1;padding:20px;border-left:4px solid #2271b1;border-radius:4px}
</style>
</head>
<body>
<div class="comment-msg">
<p>Your comment is awaiting moderation. This is a preview; your comment will be visible after it has been approved.</p>
<p><a href="/">&larr; Go back</a></p>
</div>
</body>
</html>
    <?php
}