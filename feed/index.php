<?php
require_once '/var/www/wp-honeypot/logger.php';
$log = new HoneypotLogger();
$log->log('feed.visit', ['uri' => '/feed/']);

header('Content-Type: application/rss+xml; charset=UTF-8');
echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
?>
<rss version="2.0">
<channel>
<title>My Blog</title>
<link>http://<?php echo $_SERVER['HTTP_HOST'] ?? 'localhost'; ?>/</link>
<description>Just another WordPress site</description>
<language>en-US</language>
<item>
<title>Hello world!</title>
<link>http://<?php echo $_SERVER['HTTP_HOST'] ?? 'localhost'; ?>/2024/12/hello-world/</link>
<pubDate>Wed, 25 Dec 2024 12:00:00 +0000</pubDate>
<description>Welcome to WordPress. This is your first post.</description>
</item>
<item>
<title>My Second Post</title>
<link>http://<?php echo $_SERVER['HTTP_HOST'] ?? 'localhost'; ?>/2024/12/my-second-post/</link>
<pubDate>Thu, 26 Dec 2024 12:00:00 +0000</pubDate>
<description>This is a sample post on my WordPress blog.</description>
</item>
</channel>
</rss>