<?php
/**
 * JesterTrap WP - Logger
 * Filtra IPs legítimas y detecta ataques
 */

require_once __DIR__ . '/detector.php';

class HoneypotLogger {
    private $logFile;
    private $whitelistedIPs = [
        '127.0.0.1',
        '::1',
        // Add your own trusted IPs here
    ];

    public function __construct() {
        $this->logFile = '/var/www/wp-honeypot/logs/wp-honeypot.json';
        $dir = dirname($this->logFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    public function log($eventType, $data = []) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';

        // Filtrar IPs legítimas
        if (in_array($ip, $this->whitelistedIPs)) {
            return;
        }

        // Filtrar URIs del dashboard (no son ataques)
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/honeypot') === 0) {
            return;
        }

        $entry = [
            'timestamp' => date('c'),
            'eventid' => 'wp-honeypot.' . $eventType,
            'src_ip' => $ip,
            'src_port' => $_SERVER['REMOTE_PORT'] ?? '',
            'session' => session_id() ?: substr(md5(uniqid()), 0, 12),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'host' => $_SERVER['HTTP_HOST'] ?? '',
            'uri' => $uri,
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        ];

        // Capturar body de POST
        if ($_SERVER['REQUEST_METHOD'] ?? '' === 'POST') {
            $body = file_get_contents('php://input');
            if ($body && strlen($body) < 5000) {
                $entry['post_body'] = $body;
            }
            // Capturar POST fields
            if (!empty($_POST)) {
                $entry['post_data'] = array_map(function($v) {
                    return is_string($v) ? mb_substr($v, 0, 500) : '';
                }, $_POST);
            }
        }

        // Capturar headers interesantes
        $interestingHeaders = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CF_CONNECTING_IP',
            'HTTP_REFERER',
            'HTTP_ACCEPT',
            'HTTP_ACCEPT_LANGUAGE',
            'HTTP_ACCEPT_ENCODING',
        ];
        foreach ($interestingHeaders as $h) {
            if (!empty($_SERVER[$h])) {
                $entry[strtolower(str_replace('HTTP_', '', $h))] = $_SERVER[$h];
            }
        }

        // === DETECCIÓN DE ATAQUES ===
        $detector = new AttackDetector();
        $headers = [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'host' => $_SERVER['HTTP_HOST'] ?? '',
        ];
        $body = $entry['post_body'] ?? null;
        $attacks = $detector->detect($entry['src_ip'], $uri, $entry['method'], $headers, $body);

        if (!empty($attacks)) {
            $entry['attacks'] = $attacks;
            // Marcar el evento con el tipo principal
            $entry['attack_types'] = array_unique(array_column($attacks, 'type'));
            $entry['max_severity'] = $this->maxSeverity($attacks);
        }

        $entry = array_merge($entry, $data);

        $line = json_encode($entry) . "\n";
        @file_put_contents($this->logFile, $line, FILE_APPEND | LOCK_EX);
    }

    private function maxSeverity($attacks) {
        $order = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $max = 0;
        foreach ($attacks as $a) {
            $s = $order[$a['severity']] ?? 0;
            if ($s > $max) $max = $s;
        }
        $labels = [0 => 'info', 1 => 'low', 2 => 'medium', 3 => 'high', 4 => 'critical'];
        return $labels[$max] ?? 'info';
    }
}