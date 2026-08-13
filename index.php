<?php
/**
 * JesterTrap WP - v2 Enhanced Index
 * Parece un WordPress real con base de datos
 * Responde a SQLi con errores MySQL realistas
 */
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/sqli-responder.php';

$log = new HoneypotLogger();
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Log visit
$log->log('page.visit', ['uri' => $uri, 'method' => $method]);

// === DETECTAR SQLi EN QUERY PARAMS ===
$detector = new AttackDetector();
$headers = ['user_agent' => $ua, 'referer' => $_SERVER['HTTP_REFERER'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? ''];
$body = file_get_contents('php://input') ?: null;
$attacks = $detector->detect($_SERVER['REMOTE_ADDR'] ?? '', $uri, $method, $headers, $body);

// Filtrar solo SQLi
$sqliAttacks = array_filter($attacks, fn($a) => $a['type'] === 'sqli');

// === BUSCADOR (?s=) ===
$searchQuery = $_GET['s'] ?? '';
$searchParam = '';
if ($searchQuery !== '') {
    $searchParam = $searchQuery;
}

// Si hay SQLi en cualquier parámetro, responder con error SQL
if (!empty($sqliAttacks)) {
    // Log el ataque SQLi específicamente
    $log->log('sqli.detected', [
        'uri' => $uri,
        'payload' => mb_substr($uri . ($body ?? ''), 0, 2000),
        'attacks' => $sqliAttacks,
    ]);

    $sqliPayload = '';
    foreach ($sqliAttacks as $a) {
        $sqliPayload = $a['value'];
        break;
    }

    $responder = new SQLiResponder();
    $handled = $responder->respond($sqliPayload, $uri);
    if ($handled) exit;
}

// === PÁGINA NORMAL ===
$p = isset($_GET['p']) ? (int)$_GET['p'] : 0;
$cat = $_GET['cat'] ?? '';
$author = $_GET['author'] ?? '';
$year = $_GET['year'] ?? '';
$m = $_GET['m'] ?? ''; // WP date param (YYYYMM)

// Si es búsqueda
if ($searchParam !== '') {
    showSearchResults($searchParam, $log);
    exit;
}

// Si es un post específico (?p=N)
if ($p > 0) {
    showPost($p, $log);
    exit;
}

// Si es categoría
if ($cat !== '') {
    showCategory($cat, $log);
    exit;
}

// Si es autor
if ($author !== '') {
    showAuthor($author, $log);
    exit;
}

// Si es fecha
if ($m !== '' || $year !== '') {
    showDateArchive($m ?: $year, $log);
    exit;
}

// Homepage
showHomepage($log);

// ==================== FUNCIONES ====================

function showHomepage($log) {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>My Blog – Just another WordPress site</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<link rel="alternate" type="application/rss+xml" title="My Blog » Feed" href="/feed/" />
<link rel='shortlink' href='/?p=1' />
<meta name="generator" content="WordPress 6.5.2" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="/wp-includes/wlwmanifest.xml" />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="/xmlrpc.php?rsd" />
<link rel='canonical' href='/' />
<link rel='api.w.org' href='/wp-json/' />
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<p class="site-description">Just another WordPress site</p>
<form role="search" method="get" class="search-form" action="/">
<label><span class="screen-reader-text">Search for:</span>
<input type="search" class="search-field" placeholder="Search …" value="" name="s" />
</label>
<input type="submit" class="search-submit" value="Search" />
</form>
<nav class="main-nav">
<ul>
<li><a href="/">Home</a></li>
<li><a href="/about/">About</a></li>
<li><a href="/blog/">Blog</a></li>
<li><a href="/shop/">Shop</a></li>
<li><a href="/contact/">Contact</a></li>
</ul>
</nav>
</div>
<div class="site-main">
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="/2024/12/hello-world/">Hello world!</a></h2>
<p class="wp-block-post-date">December 25, 2024</p>
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
<p class="post-meta">Posted in <a href="/category/uncategorized/">Uncategorized</a> | <a href="/2024/12/hello-world/#comments">1 Comment</a> | <a href="/2024/12/hello-world/feed/">Comments Feed</a></p>
</article>
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="/2024/12/my-second-post/">My Second Post</a></h2>
<p class="wp-block-post-date">December 26, 2024</p>
<p>This is a sample post on my WordPress blog. Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
<p class="post-meta">Posted in <a href="/category/uncategorized/">Uncategorized</a> | <a href="/2024/12/my-second-post/#comments">Comments</a></p>
</article>
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="/2024/12/another-interesting-post/">Another Interesting Post</a></h2>
<p class="wp-block-post-date">December 27, 2024</p>
<p>Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
<p class="post-meta">Posted in <a href="/category/news/">News</a></p>
</article>
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="/2025/01/10-tips-for-better-blogging/">10 Tips for Better Blogging</a></h2>
<p class="wp-block-post-date">January 10, 2025</p>
<p>Here are some practical tips to improve your blogging experience and engage your readers.</p>
<p class="post-meta">Posted in <a href="/category/tips/">Tips</a> | <a href="/2025/01/10-tips-for-better-blogging/#comments">3 Comments</a></p>
</article>
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="/2025/02/the-future-of-web-design/">The Future of Web Design</a></h2>
<p class="wp-block-post-date">February 15, 2025</p>
<p>Exploring upcoming trends in web design and how they shape user experience.</p>
<p class="post-meta">Posted in <a href="/category/news/">News</a></p>
</article>
</div>
<div class="site-sidebar">
<h3>Recent Posts</h3>
<ul>
<li><a href="/2024/12/hello-world/">Hello world!</a></li>
<li><a href="/2024/12/my-second-post/">My Second Post</a></li>
<li><a href="/2024/12/another-interesting-post/">Another Interesting Post</a></li>
<li><a href="/2025/01/10-tips-for-better-blogging/">10 Tips for Better Blogging</a></li>
<li><a href="/2025/02/the-future-of-web-design/">The Future of Web Design</a></li>
</ul>
<h3>Categories</h3>
<ul>
<li><a href="/category/uncategorized/">Uncategorized</a></li>
<li><a href="/category/news/">News</a></li>
<li><a href="/category/tips/">Tips</a></li>
</ul>
<h3>Archives</h3>
<ul>
<li><a href="/2025/02/">February 2025</a></li>
<li><a href="/2025/01/">January 2025</a></li>
<li><a href="/2024/12/">December 2024</a></li>
</ul>
<h3>Meta</h3>
<ul>
<li><a href="/wp-admin/">Site Admin</a></li>
<li><a href="/wp-login.php">Log in</a></li>
<li><a href="/feed/">Entries <abbr title="Really Simple Syndication">RSS</abbr></a></li>
<li><a href="/wp-comments-post.php">Comments RSS</a></li>
</ul>
</div>
<div class="site-footer">
<p>Powered by <a href="https://wordpress.org/">WordPress</a></p>
<p><a href="/wp-login.php">Login</a> | <a href="/wp-admin/">Admin</a> | <a href="/xmlrpc.php">XML-RPC</a> | <a href="/wp-json/">REST API</a></p>
</div>
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
<script src="/wp-includes/js/jquery/jquery-migrate.min.js"></script>
</body>
</html>
    <?php
}

function showSearchResults($query, $log) {
    $log->log('search.query', ['query' => $query]);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Search Results for "<?php echo htmlspecialchars($query); ?>" – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<meta name="generator" content="WordPress 6.5.2" />
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<form role="search" method="get" class="search-form" action="/">
<input type="search" class="search-field" placeholder="Search …" value="<?php echo htmlspecialchars($query); ?>" name="s" />
<input type="submit" class="search-submit" value="Search" />
</form>
</div>
<div class="site-main">
<h2 class="page-title">Search Results for: <?php echo htmlspecialchars($query); ?></h2>
<?php
// Fake results - siempre mostrar algunos
$fakeResults = [
    ['title' => 'Hello world!', 'excerpt' => 'Welcome to WordPress. This is your first post...', 'url' => '/2024/12/hello-world/', 'date' => 'December 25, 2024'],
    ['title' => '10 Tips for Better Blogging', 'excerpt' => 'Here are some practical tips to improve your blogging...', 'url' => '/2025/01/10-tips-for-better-blogging/', 'date' => 'January 10, 2025'],
    ['title' => 'The Future of Web Design', 'excerpt' => 'Exploring upcoming trends in web design...', 'url' => '/2025/02/the-future-of-web-design/', 'date' => 'February 15, 2025'],
];
foreach ($fakeResults as $r):
?>
<article class="wp-block-post">
<h2 class="wp-block-post-title"><a href="<?php echo $r['url']; ?>"><?php echo $r['title']; ?></a></h2>
<p class="wp-block-post-date"><?php echo $r['date']; ?></p>
<p><?php echo $r['excerpt']; ?></p>
</article>
<?php endforeach; ?>
<p class="no-results">Showing 1–3 of 3 results</p>
</div>
<div class="site-footer">
<p>Powered by <a href="https://wordpress.org/">WordPress</a></p>
</div>
</body>
</html>
    <?php
}

function showPost($id, $log) {
    $log->log('post.view', ['post_id' => $id]);
    $posts = [
        1 => ['title' => 'Hello world!', 'date' => 'December 25, 2024', 'author' => 'admin', 'content' => 'Welcome to WordPress. This is your first post. Edit or delete it, then start writing! This is a sample post to show how your blog looks. You can write about anything you want — your hobbies, your work, your life. WordPress makes it easy to share your thoughts with the world.'],
        2 => ['title' => 'My Second Post', 'date' => 'December 26, 2024', 'author' => 'admin', 'content' => 'This is a sample post on my WordPress blog. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.'],
        3 => ['title' => 'Another Interesting Post', 'date' => 'December 27, 2024', 'author' => 'editor', 'content' => 'Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.'],
        4 => ['title' => '10 Tips for Better Blogging', 'date' => 'January 10, 2025', 'author' => 'John Writer', 'content' => 'Here are some practical tips to improve your blogging experience and engage your readers. 1. Write regularly. 2. Be authentic. 3. Use images. 4. Engage with comments. 5. Optimize for SEO.'],
        5 => ['title' => 'The Future of Web Design', 'date' => 'February 15, 2025', 'author' => 'admin', 'content' => 'Exploring upcoming trends in web design and how they shape user experience. From minimalism to bold typography, the future of web design is exciting.'],
    ];
    $post = $posts[$id] ?? null;
    if (!$post) {
        http_response_code(404);
        echo "<h1>404 Not Found</h1><p>Sorry, that post was not found.</p>";
        return;
    }
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo $post['title']; ?> – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<meta name="generator" content="WordPress 6.5.2" />
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<form role="search" method="get" class="search-form" action="/">
<input type="search" class="search-field" placeholder="Search …" value="" name="s" />
<input type="submit" class="search-submit" value="Search" />
</form>
</div>
<div class="site-main">
<article class="wp-block-post single">
<h2 class="wp-block-post-title"><?php echo $post['title']; ?></h2>
<p class="wp-block-post-date"><?php echo $post['date']; ?> by <?php echo $post['author']; ?></p>
<div class="post-content"><?php echo $post['content']; ?></div>
</article>
<div id="comments" class="comments-area">
<h3 class="comments-title">1 thought on "<?php echo $post['title']; ?>"</h3>
<ol class="comment-list">
<li class="comment">
<div class="comment-body">
<cite class="fn">Mr WordPress</cite> <span class="says">says:</span>
<p>Hi, this is a comment. To delete a comment, just log in and view the post's comments. There you will have the option to edit or delete them.</p>
</div>
</li>
</ol>
<div id="respond" class="comment-respond">
<h3 id="reply-title" class="comment-reply-title">Leave a Reply</h3>
<form action="/wp-comments-post.php" method="post" id="commentform" class="comment-form">
<p class="comment-form-author"><label for="author">Name</label><input id="author" name="author" type="text" value="" size="30" /></p>
<p class="comment-form-email"><label for="email">Email</label><input id="email" name="email" type="text" value="" size="30" /></p>
<p class="comment-form-url"><label for="url">Website</label><input id="url" name="url" type="text" value="" size="30" /></p>
<p class="comment-form-comment"><label for="comment">Comment</label><textarea id="comment" name="comment" cols="45" rows="5"></textarea></p>
<input type="hidden" name="comment_post_ID" value="<?php echo $id; ?>" id="comment_post_ID" />
<p class="form-submit"><input name="submit" type="submit" id="submit" class="submit" value="Post Comment" /></p>
</form>
</div>
</div>
</div>
<div class="site-footer">
<p>Powered by <a href="https://wordpress.org/">WordPress</a></p>
</div>
</body>
</html>
    <?php
}

function showCategory($cat, $log) {
    $log->log('category.view', ['category' => $cat]);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Category: <?php echo htmlspecialchars($cat); ?> – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<meta name="generator" content="WordPress 6.5.2" />
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<form role="search" method="get" action="/"><input type="search" name="s" placeholder="Search..." /><input type="submit" value="Search" /></form>
</div>
<div class="site-main">
<h2 class="page-title">Category: <?php echo htmlspecialchars($cat); ?></h2>
<article class="wp-block-post">
<h2><a href="/2024/12/hello-world/">Hello world!</a></h2>
<p>December 25, 2024</p>
<p>Welcome to WordPress...</p>
</article>
<article class="wp-block-post">
<h2><a href="/2025/01/10-tips-for-better-blogging/">10 Tips for Better Blogging</a></h2>
<p>January 10, 2025</p>
<p>Here are some practical tips...</p>
</article>
</div>
<div class="site-footer"><p>Powered by WordPress</p></div>
</body>
</html>
    <?php
}

function showAuthor($author, $log) {
    $log->log('author.view', ['author' => $author]);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Author: <?php echo htmlspecialchars($author); ?> – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
</head>
<body>
<div class="site-header"><h1><a href="/">My Blog</a></h1></div>
<div class="site-main">
<h2>Posts by <?php echo htmlspecialchars($author); ?></h2>
<article class="wp-block-post">
<h2><a href="/2024/12/hello-world/">Hello world!</a></h2>
<p>December 25, 2024</p>
</article>
</div>
<div class="site-footer"><p>Powered by WordPress</p></div>
</body>
</html>
    <?php
}

function showDateArchive($date, $log) {
    $log->log('archive.view', ['date' => $date]);
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Archives – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
</head>
<body>
<div class="site-header"><h1><a href="/">My Blog</a></h1></div>
<div class="site-main">
<h2>Archive for <?php echo htmlspecialchars($date); ?></h2>
<article class="wp-block-post">
<h2><a href="/2024/12/hello-world/">Hello world!</a></h2>
<p>December 25, 2024</p>
</article>
</div>
<div class="site-footer"><p>Powered by WordPress</p></div>
</body>
</html>
    <?php
}