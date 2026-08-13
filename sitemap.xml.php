<?php
/**
 * JesterTrap WP - Fake sitemap.xml
 * Genera un sitemap con contenido falso para atraer crawlers y bots
 */
require_once __DIR__ . '/logger.php';

$log = new HoneypotLogger();

$log->log('sitemap.request', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
]);

header('Content-Type: application/xml; charset=UTF-8');
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";

$pages = [
    '/', '/about/', '/contact/', '/blog/', '/blog/hello-world/',
    '/blog/my-first-post/', '/blog/uncategorized/test/',
    '/sample-page/', '/privacy-policy/', '/terms-of-service/',
    '/2024/', '/2024/01/', '/2024/02/', '/2024/03/',
    '/category/uncategorized/', '/category/news/',
    '/author/admin/', '/feed/',
];

foreach ($pages as $p) {
    echo "  <url>\n";
    echo "    <loc>http://your-domain.com$p</loc>\n";
    echo "    <lastmod>2024-06-15</lastmod>\n";
    echo "    <changefreq>weekly</changefreq>\n";
    echo "    <priority>0.8</priority>\n";
    echo "  </url>\n";
}

echo '</urlset>';