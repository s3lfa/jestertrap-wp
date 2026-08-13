# 🍯 JesterTrap WP — WordPress Honeypot

A fake WordPress site designed to attract, detect, and log attacks from bots, scanners, and malicious actors. It simulates a real WordPress installation with login pages, XML-RPC, REST API, shop, and plugin directories — while silently capturing every attack attempt.

## Features

### Attack Surface Simulation
- **`wp-login.php`** — Fake login page (captures usernames/passwords, always responds "incorrect password" to keep attackers trying)
- **`xmlrpc.php`** — Full fake XML-RPC server (responds to `system.listMethods`, `wp.getUsersBlogs`, `pingback.ping`, `system.multicall`, etc.)
- **`wp-json/` REST API** — Fake WordPress REST API v2 + WooCommerce v3 (responds to enumeration and SQLi attempts with realistic MySQL errors)
- **`wp-admin/`** — Fake admin panel with `admin-ajax.php` and `setup-config.php`
- **`shop/`** — Fake WooCommerce shop page
- **`wp-content/plugins/`** — Fake plugin directories (Elementor, WooCommerce, Wordfence, Duplicator, WPForms, etc.) to attract plugin-specific exploits
- **`wp-comments-post.php`** — Fake comment submission endpoint
- **`wp-trackback.php`** — Fake trackback endpoint
- **`sitemap.xml.php`** — Dynamic sitemap generator
- **`robots.txt`** — Standard WordPress robots.txt
- **`readme.html`** — Fake WordPress readme

### Attack Detection
The built-in **AttackDetector** class identifies and classifies:
- **SQL Injection** (UNION SELECT, boolean-based, time-based, error-based, etc.)
- **XSS** (reflected, stored, DOM-based)
- **LFI/RFI** (path traversal, PHP wrappers, `/etc/passwd`, etc.)
- **Command Injection** (`;`, `|`, `&&`, backticks, `$(...)`, `system()`, `exec()`, etc.)
- **PHP Code Injection** (`eval()`, `assert()`, `include()`, `$_GET`, etc.)
- **SSTI** (Server-Side Template Injection — `{{...}}`, `{%...%}`, `${...}`)
- **XPath Injection**
- **CRLF Injection**
- **Open Redirect**
- **SSRF**
- **Suspicious scanners** (sqlmap, nikto, nmap, wpscan, nuclei, ffuf, etc.)

Each attack is logged with severity level (critical/high/medium/low), pattern matched, source input, and full request context.

### Logging
- All attacks logged to `logs/wp-honeypot.json` (JSON Lines format)
- Each entry includes: timestamp, event type, source IP, port, session, user agent, URI, method, POST data, interesting headers, detected attacks
- Whitelisted IPs are filtered out (configure in `logger.php`)
- Automatic attack classification with `attack_types` and `max_severity` fields

### SQLi Responder
`sqli-responder.php` generates realistic MySQL error messages when SQL injection is detected, encouraging attackers to continue probing (more data for you).

## Installation

### Requirements
- PHP 8.0+ with PHP-FPM
- Nginx
- Linux server (tested on Ubuntu)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/youruser/wp-honeypot.git
   cd wp-honeypot
   ```

2. Copy files to your web root:
   ```bash
   sudo cp -r . /var/www/wp-honeypot/
   sudo chown -R www-data:www-data /var/www/wp-honeypot/
   sudo mkdir -p /var/www/wp-honeypot/logs
   sudo chown www-data:www-data /var/www/wp-honeypot/logs
   ```

3. Configure your whitelist in `logger.php`:
   ```php
   private $whitelistedIPs = [
       '127.0.0.1',
       '::1',
       'your.trusted.ip.here',
   ];
   ```

4. Copy the Nginx config (adjust as needed):
   ```bash
   sudo cp nginx.conf /etc/nginx/sites-available/wp-honeypot
   sudo ln -s /etc/nginx/sites-available/wp-honeypot /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```

5. Make sure the server is exposed on port 80 (the honeypot port). **Do not run a real website on the same port.**

### Optional: Case Extraction
`extract-cases.py` can extract interesting attack sessions and send them to an external API for analysis:

```bash
export HONEYPOT_SYNC_URL="https://your-server.example.com/api/cases"
export HONEYPOT_SYNC_TOKEN="your-token"
python3 extract-cases.py
```

## File Structure

```
wp-honeypot/
├── index.php                    # Main site (fake WordPress homepage)
├── wp-login.php                 # Fake login page
├── xmlrpc.php                   # Fake XML-RPC server
├── logger.php                   # Logging engine + attack classifier
├── detector.php                 # Attack detection (regex patterns)
├── sqli-responder.php           # Realistic MySQL error generator
├── wp-comments-post.php         # Fake comment endpoint
├── wp-trackback.php             # Fake trackback endpoint
├── sitemap.xml.php              # Dynamic sitemap
├── robots.txt                   # WordPress robots.txt
├── readme.html                  # Fake WordPress readme
├── generate_wp_data.py          # Dashboard data generator
├── extract-cases.py             # Case extraction tool
├── nginx.conf                   # Example Nginx configuration
├── logs/                        # Attack logs (JSON Lines)
├── wp-admin/
│   ├── index.php                # Fake admin dashboard
│   ├── admin-ajax.php           # Fake AJAX handler
│   ├── setup-config.php         # Fake setup wizard
│   └── css/
│       └── login.min.css        # WordPress login styles
├── wp-content/
│   ├── themes/twentytwentyfour/
│   │   └── style.css            # Fake theme
│   └── plugins/                 # Fake plugin directories
│       ├── akismet/index.php
│       ├── contact-form-7/index.php
│       ├── duplicator/index.php
│       ├── elementor/index.php
│       ├── woocommerce/index.php
│       ├── wordfence/index.php
│       ├── wpfilemanager/index.php
│       ├── wpforms-lite/index.php
│       └── yoast-seo/index.php
├── wp-json/
│   ├── index.php                # REST API root
│   ├── wp/v2/index.php          # WP REST API v2
│   └── wc/v3/index.php          # WooCommerce REST API v3
├── wp-includes/
│   ├── version.php              # Fake WordPress version
│   └── js/jquery/               # jQuery (for page realism)
└── shop/
    └── index.php                # Fake WooCommerce shop
```

## ⚠️ Important

- **Run this on a dedicated server/VPS.** Do not run on a production web server.
- **The honeypot port (80) must be open to the internet** — that's how attackers find it.
- **Never store real data on the honeypot server.**
- **Review your local laws** regarding honeypot deployment before running.
- Logs may contain sensitive data (attacker IPs, attempted credentials, payloads) — handle accordingly.

## License

MIT — use it, modify it, deploy it. Attribution appreciated but not required.

## Credits

Built for [JesterTrap](https://github.com/youruser) — a self-hosted threat intelligence platform.