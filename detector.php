<?php
/**
 * JesterTrap WP - Attack Detector
 * Detecta SQLi, XSS, LFI/RFI, command injection, path traversal, PHP injection y más
 */

class AttackDetector {

    private $patterns = [];
    private $suspiciousUserAgents = [];

    public function __construct() {
        $this->patterns = [
            // SQL Injection
            'sqli' => [
                '/(\bUNION\b\s+\bSELECT\b)/i',
                '/(\bSELECT\b\s+.*\bFROM\b)/i',
                '/(\bINSERT\b\s+\bINTO\b)/i',
                '/(\bUPDATE\b\s+.*\bSET\b)/i',
                '/(\bDELETE\b\s+\bFROM\b)/i',
                '/(\bDROP\b\s+\bTABLE\b)/i',
                '/(\bCREATE\b\s+\bTABLE\b)/i',
                '/(\bALTER\b\s+\bTABLE\b)/i',
                "/('.*OR.*'.*=.*')/i",
                "/('.*OR.*1\s*=\s*1)/i",
                "/('OR'1'='1)/i",
                "/('OR'1=1)/i",
                '/(\bOR\b\s+\d+\s*=\s*\d+)/i',
                "/(')\s*(--|#)/i",
                '/(\bSLEEP\s*\()/i',
                '/(\bBENCHMARK\s*\()/i',
                '/(\bWAITFOR\b\s+\bDELAY\b)/i',
                '/(\bLOAD_FILE\s*\()/i',
                '/(\bINTO\s+OUTFILE\b)/i',
                '/(\bINFORMATION_SCHEMA\b)/i',
                '/(\bCONCAT\s*\()/i',
                '/(\bGROUP_BY\b.*\bHAVING\b)/i',
                '/(\bORDER\s+BY\b\s+\d+)/i',
                '/(\bEXTRACTVALUE\s*\()/i',
                '/(\bUPDATEXML\s*\()/i',
            ],
            // XSS
            'xss' => [
                '/(<script[^>]*>.*<\/script>)/is',
                '/(onerror\s*=)/i',
                '/(onload\s*=)/i',
                '/(onclick\s*=)/i',
                '/(onmouseover\s*=)/i',
                '/(javascript:)/i',
                '/(<img[^>]+src[^>]+onerror)/i',
                '/(<svg[^>]*>.*<\/svg>)/is',
                '/(<iframe[^>]*>)/i',
                '/(alert\s*\()/i',
                '/(prompt\s*\()/i',
                '/(confirm\s*\()/i',
                '/(document\.cookie)/i',
                '/(document\.location)/i',
                '/(window\.location)/i',
                '/(eval\s*\()/i',
                '/(String\.fromCharCode)/i',
                '/(encodeURIComponent\s*\()/i',
                '/(document\.write)/i',
                '/(<body[^>]+onload)/i',
                '/(<input[^>]+onfocus)/i',
                '/(onfocus\s*=)/i',
            ],
            // LFI / RFI
            'lfi_rfi' => [
                '/(\.\.\/\.\.\/\.\.\/)/i',
                '/(\.\.%2f\.\.%2f\.\.%2f)/i',
                '/(%2e%2e%2f)/i',
                '/(\/etc\/passwd)/i',
                '/(\/etc\/shadow)/i',
                '/(\/etc\/hosts)/i',
                '/(\/proc\/self\/)/i',
                '/(php:\/\/input)/i',
                '/(php:\/\/filter)/i',
                '/(file:\/\/)/i',
                '/(data:\/\/)/i',
                '/(expect:\/\/)/i',
                '/(\.\.\\\\)/i',
                '/(\/windows\/system32)/i',
                '/(\/boot\.ini)/i',
                '/(\/win\.ini)/i',
                "/(\.\.;)/i",
                '/(\/etc\/group)/i',
                '/(\/var\/log\/)/i',
            ],
            // Command Injection
            'cmd_injection' => [
                '/(;[ \t]*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby)\b)/i',
                '/(\|[ \t]*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh)\b)/i',
                '/(&&[ \t]*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh)\b)/i',
                '/(\|\|[ \t]*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh)\b)/i',
                '/(`[^`]+`)/',
                '/(\$\([^)]+\))/',
                '/(\bsystem\s*\()/i',
                '/(\bexec\s*\()/i',
                '/(\bpassthru\s*\()/i',
                '/(\bshell_exec\s*\()/i',
                '/(\bpopen\s*\()/i',
                '/(\bproc_open\s*\()/i',
                '/(\bwget\s+http)/i',
                '/(\bcurl\s+http)/i',
                '/(\bnc\s+-l)/i',
                '/(\bpython\s+-c)/i',
                '/(\bperl\s+-e)/i',
                '/(\bruby\s+-e)/i',
                '/(\bchmod\s+[0-7]+)/i',
                '/(\bkill\s+-9)/i',
                '/(\bsudo\b)/i',
                '/(\bsu\b\s)/i',
            ],
            // PHP Code Injection
            'php_injection' => [
                '/(\beval\s*\()/i',
                '/(\bassert\s*\()/i',
                '/(\bcreate_function\s*\()/i',
                '/(\bcall_user_func\s*\()/i',
                '/(\binclude\s*\()/i',
                '/(\brequire\s*\()/i',
                '/(\binclude_once\s*\()/i',
                '/(\brequire_once\s*\()/i',
                '/(\b\$_GET\b)/i',
                '/(\b\$_POST\b)/i',
                '/(\b\$_REQUEST\b)/i',
                '/(\b\$_FILES\b)/i',
                '/(\b\$_SERVER\b)/i',
                '/(\bGLOBALS\b)/i',
                '/(\bextract\s*\()/i',
            ],
            // SSTI (Server-Side Template Injection)
            'ssti' => [
                '/(\{\{.*\}\})/s',
                '/(\{%.*%\})/s',
                '/(#\{.*\})/s',
                '/(\$\{.*\})/s',
                '/(\{=.*\})/s',
            ],
            // Xpath Injection
            'xpath' => [
                "/(\bOR\b.*'.*'.*=.*'.*')/i",
                "/(\bAND\b.*'.*'.*=.*'.*')/i",
                '/(\bcount\s*\()/i',
                '/(\bstring\s*\()/i',
                '/(\bsubstring\s*\()/i',
            ],
            // CRLF Injection
            'crlf' => [
                '/(%0d%0a)/i',
                '/(%0a)/i',
                "/(\r\n)/",
                "/(\n)/",
            ],
            // Open Redirect
            'open_redirect' => [
                '/(\?redirect=\/\/)/i',
                '/(\?url=\/\/)/i',
                '/(\?next=\/\/)/i',
                '/(\?return=\/\/)/i',
                '/(\?goto=\/\/)/i',
                '/(\?to=\/\/)/i',
            ],
            // SSRF
            'ssrf' => [
                '/(\burl=http:\/\/)/i',
                '/(\burl=https:\/\/)/i',
                '/(\bhost=)/i',
                '/(\btarget=)/i',
                '/(\bfetch=)/i',
                '/(\bsource=)/i',
            ],
        ];

        $this->suspiciousUserAgents = [
            '/sqlmap/i',
            '/nikto/i',
            '/nmap/i',
            '/masscan/i',
            '/dirbuster/i',
            '/gobuster/i',
            '/wpscan/i',
            '/acunetix/i',
            '/nessus/i',
            '/burp/i',
            '/hydra/i',
            '/metasploit/i',
            '/nuclei/i',
            '/httpx/i',
            '/crawlergo/i',
            '/subfinder/i',
            '/ffuf/i',
            '/wfuzz/i',
            '/arjun/i',
            '/whatweb/i',
            '/zgrab/i',
            '/go-http-client/i',
            '/python-requests/i',
            '/curl\//i',
            '/wget\//i',
            '/libwww-perl/i',
            '/pycurl/i',
        ];
    }

    /**
     * Analiza una petición y detecta ataques
     */
    public function detect($source, $uri, $method, $headers = [], $body = null) {
        $attacks = [];

        $inputs = [
            'uri' => $uri,
            'method' => $method,
            'body' => is_string($body) ? $body : '',
            'user_agent' => $headers['user_agent'] ?? '',
            'referer' => $headers['referer'] ?? '',
            'host' => $headers['host'] ?? '',
        ];

        // Query string params
        $queryString = parse_url($uri, PHP_URL_QUERY) ?: '';
        if ($queryString) {
            parse_str($queryString, $params);
            foreach ($params as $key => $value) {
                $inputs['param_' . $key] = is_string($value) ? $value : '';
            }
        }

        // POST params
        if (!empty($_POST)) {
            foreach ($_POST as $key => $value) {
                $inputs['post_' . $key] = is_string($value) ? $value : '';
            }
        }

        // Detectar por patrones
        foreach ($this->patterns as $attackType => $regexList) {
            foreach ($regexList as $regex) {
                foreach ($inputs as $sourceName => $input) {
                    if (!is_string($input)) continue;
                    if (@preg_match($regex, $input)) {
                        $attacks[] = [
                            'type' => $attackType,
                            'pattern' => $regex,
                            'source' => $sourceName,
                            'value' => mb_substr($input, 0, 200),
                            'severity' => $this->getSeverity($attackType),
                        ];
                        break 2;
                    }
                }
            }
        }

        // Detectar User-Agent sospechoso
        if (!empty($headers['user_agent'])) {
            foreach ($this->suspiciousUserAgents as $agentRegex) {
                if (@preg_match($agentRegex, $headers['user_agent'])) {
                    $attacks[] = [
                        'type' => 'suspicious_scanner',
                        'pattern' => $agentRegex,
                        'source' => 'user_agent',
                        'value' => $headers['user_agent'],
                        'severity' => 'medium',
                    ];
                    break;
                }
            }
        }

        return $attacks;
    }

    private function getSeverity($type) {
        $severities = [
            'sqli' => 'critical',
            'xss' => 'high',
            'lfi_rfi' => 'critical',
            'cmd_injection' => 'critical',
            'php_injection' => 'critical',
            'ssti' => 'high',
            'xpath' => 'high',
            'crlf' => 'medium',
            'open_redirect' => 'medium',
            'ssrf' => 'high',
            'suspicious_scanner' => 'medium',
        ];
        return $severities[$type] ?? 'low';
    }
}