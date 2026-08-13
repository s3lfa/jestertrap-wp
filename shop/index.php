<?php
/**
 * JesterTrap WP - WooCommerce Fake Shop
 * /shop/ con productos, /product/{slug}/ individual
 * Vector adicional de SQLi vía parámetros de producto
 */
require_once __DIR__ . '/../logger.php';
require_once __DIR__ . '/../sqli-responder.php';

$log = new HoneypotLogger();
$uri = $_SERVER['REQUEST_URI'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

$log->log('shop.visit', ['uri' => $uri, 'ua' => $ua]);

// Detectar SQLi
$detector = new AttackDetector();
$headers = ['user_agent' => $ua, 'referer' => $_SERVER['HTTP_REFERER'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? ''];
$body = file_get_contents('php://input') ?: null;
$attacks = $detector->detect($_SERVER['REMOTE_ADDR'] ?? '', $uri, $_SERVER['REQUEST_METHOD'] ?? 'GET', $headers, $body);
$sqliAttacks = array_filter($attacks, fn($a) => $a['type'] === 'sqli');

if (!empty($sqliAttacks)) {
    $log->log('sqli.detected', [
        'uri' => $uri,
        'payload' => mb_substr($uri . ($body ?? ''), 0, 2000),
        'attacks' => $sqliAttacks,
        'endpoint' => 'shop',
    ]);
    $responder = new SQLiResponder();
    $responder->respond($sqliAttacks[0]['value'], $uri);
    exit;
}

$products = [
    ['id' => 1, 'name' => 'Premium WordPress Theme', 'price' => '$49.99', 'regular_price' => '$59.99', 'sale' => true, 'image' => 'https://via.placeholder.com/300x200', 'desc' => 'A premium WordPress theme with modern design and SEO optimization.', 'slug' => 'premium-theme', 'category' => 'Themes'],
    ['id' => 2, 'name' => 'SEO Plugin Pro', 'price' => '$29.99', 'regular_price' => '$29.99', 'sale' => false, 'desc' => 'Professional SEO plugin with advanced features.', 'slug' => 'seo-plugin-pro', 'category' => 'Plugins'],
    ['id' => 3, 'name' => 'Security Bundle', 'price' => '$99.00', 'regular_price' => '$149.00', 'sale' => true, 'desc' => 'Complete security suite for WordPress sites.', 'slug' => 'security-bundle', 'category' => 'Security'],
    ['id' => 4, 'name' => 'Backup Solution', 'price' => '$19.99', 'regular_price' => '$19.99', 'sale' => false, 'desc' => 'Automated backup and restore solution.', 'slug' => 'backup-solution', 'category' => 'Plugins'],
    ['id' => 5, 'name' => 'Page Builder Pro', 'price' => '$39.99', 'regular_price' => '$49.99', 'sale' => true, 'desc' => 'Drag and drop page builder with 200+ templates.', 'slug' => 'page-builder-pro', 'category' => 'Plugins'],
    ['id' => 6, 'name' => 'E-commerce Theme', 'price' => '$59.99', 'regular_price' => '$59.99', 'sale' => false, 'desc' => 'WooCommerce-ready theme for online stores.', 'slug' => 'ecommerce-theme', 'category' => 'Themes'],
];

// Detectar si es producto individual
if (preg_match('#/product/([^/]+)#', $uri, $m)) {
    $slug = $m[1];
    $product = array_filter($products, fn($p) => $p['slug'] === $slug);
    if (!empty($product)) {
        showProduct(array_values($product)[0]);
    } else {
        http_response_code(404);
        echo "<h1>Product not found</h1>";
    }
    exit;
}

// Listado de tienda
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shop – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<meta name="generator" content="WordPress 6.5.2" />
<style>
.products { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 20px 0; }
.product-card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; text-align: center; }
.product-card img { max-width: 100%; height: auto; border-radius: 4px; }
.product-card h3 { margin: 10px 0 5px; }
.product-card .price { color: #2271b1; font-size: 18px; font-weight: bold; }
.product-card .sale-badge { background: #d63638; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
.woocommerce-breadcrumb { padding: 10px 0; color: #666; }
</style>
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<nav class="main-nav">
<ul>
<li><a href="/">Home</a></li>
<li><a href="/about/">About</a></li>
<li><a href="/blog/">Blog</a></li>
<li><a href="/shop/">Shop</a> ✦</li>
<li><a href="/contact/">Contact</a></li>
</ul>
</nav>
</div>
<div class="site-main">
<nav class="woocommerce-breadcrumb"><a href="/">Home</a> / Shop</nav>
<h2>Shop</h2>
<div class="products">
<?php foreach ($products as $p): ?>
<div class="product-card">
<img src="<?php echo $p['image']; ?>" alt="<?php echo $p['name']; ?>">
<h3><a href="/product/<?php echo $p['slug']; ?>/"><?php echo $p['name']; ?></a></h3>
<p class="price"><?php echo $p['price']; ?>
<?php if ($p['sale']): ?> <span class="sale-badge">Sale!</span><?php endif; ?>
</p>
<p><?php echo $p['desc']; ?></p>
<a href="/product/<?php echo $p['slug']; ?>/?add-to-cart=<?php echo $p['id']; ?>" class="button">Add to cart</a>
</div>
<?php endforeach; ?>
</div>
</div>
<div class="site-footer">
<p>Powered by <a href="https://wordpress.org/">WordPress</a> &amp; <a href="https://woocommerce.com/">WooCommerce</a></p>
</div>
</body>
</html>
<?php

function showProduct($p) {
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo $p['name']; ?> – My Blog</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<style>
.product-detail { display: flex; gap: 30px; padding: 20px 0; }
.product-detail img { max-width: 400px; border-radius: 8px; }
.product-info h1 { margin-top: 0; }
.product-info .price { font-size: 24px; color: #2271b1; }
</style>
</head>
<body>
<div class="site-header">
<h1 class="site-title"><a href="/">My Blog</a></h1>
<nav class="main-nav">
<ul>
<li><a href="/">Home</a></li>
<li><a href="/shop/">Shop</a></li>
</ul>
</nav>
</div>
<div class="site-main">
<nav class="woocommerce-breadcrumb"><a href="/">Home</a> / <a href="/shop/">Shop</a> / <?php echo $p['name']; ?></nav>
<div class="product-detail">
<div class="product-image">
<img src="<?php echo $p['image']; ?>" alt="<?php echo $p['name']; ?>">
</div>
<div class="product-info">
<h1><?php echo $p['name']; ?></h1>
<p class="price"><?php echo $p['price']; ?></p>
<p>Category: <?php echo $p['category']; ?></p>
<p><?php echo $p['desc']; ?></p>
<form action="/shop/" method="post" class="cart">
<input type="hidden" name="product_id" value="<?php echo $p['id']; ?>" />
<button type="submit" class="button alt">Add to cart</button>
</form>
</div>
</div>
<div id="comments" class="comments-area">
<h3>Reviews (2)</h3>
<div class="review"><strong>Jane D.</strong> ★★★★★<p>Excellent product, highly recommended!</p></div>
<div class="review"><strong>Mark S.</strong> ★★★★☆<p>Great value for the price.</p></div>
<div id="respond">
<h3>Write a review</h3>
<form action="/wp-comments-post.php" method="post">
<p><input type="text" name="author" placeholder="Your name" /></p>
<p><input type="email" name="email" placeholder="Your email" /></p>
<p><textarea name="comment" rows="4" placeholder="Your review"></textarea></p>
<input type="hidden" name="comment_post_ID" value="<?php echo $p['id']; ?>" />
<p><button type="submit">Submit Review</button></p>
</form>
</div>
</div>
</div>
<div class="site-footer">
<p>Powered by WordPress &amp; WooCommerce</p>
</div>
</body>
</html>
    <?php
}