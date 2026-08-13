<?php
/**
 * JesterTrap WP - SQL Injection Responder
 * Genera errores MySQL realistas cuando se detecta SQLi
 * Hace creer al atacante que su inyección está funcionando contra una BD real
 */

class SQLiResponder {

    // Datos fake de tablas WordPress
    private $fakeTables = [
        'wp_users' => [
            ['ID' => 1, 'user_login' => 'admin', 'user_pass' => '$P$BXbQ1MkTJqMzQ3NzRkMjY5MTIwMDAwMTIzNDU2Nzg', 'user_email' => 'admin@myblog.com', 'display_name' => 'Admin', 'user_registered' => '2024-12-25 10:00:00'],
            ['ID' => 2, 'user_login' => 'editor', 'user_pass' => '$P$BXbQ2NkTJqMzQ3NzRkMjY5MTIwMDAwMTIzNDU2Nzk', 'user_email' => 'editor@myblog.com', 'display_name' => 'Editor', 'user_registered' => '2024-12-26 12:00:00'],
            ['ID' => 3, 'user_login' => 'author1', 'user_pass' => '$P$BXbQ3NkTJqMzQ3NzRkMjY5MTIwMDAwMTIzNDU2N80', 'user_email' => 'author@myblog.com', 'display_name' => 'John Writer', 'user_registered' => '2025-01-05 09:30:00'],
        ],
        'wp_posts' => [
            ['ID' => 1, 'post_title' => 'Hello world!', 'post_author' => '1', 'post_date' => '2024-12-25 10:00:00', 'post_status' => 'publish', 'post_type' => 'post'],
            ['ID' => 2, 'post_title' => 'My Second Post', 'post_author' => '1', 'post_date' => '2024-12-26 11:00:00', 'post_status' => 'publish', 'post_type' => 'post'],
            ['ID' => 3, 'post_title' => 'Another Interesting Post', 'post_author' => '2', 'post_date' => '2024-12-27 14:00:00', 'post_status' => 'publish', 'post_type' => 'post'],
            ['ID' => 4, 'post_title' => '10 Tips for Better Blogging', 'post_author' => '3', 'post_date' => '2025-01-10 09:00:00', 'post_status' => 'publish', 'post_type' => 'post'],
            ['ID' => 5, 'post_title' => 'The Future of Web Design', 'post_author' => '1', 'post_date' => '2025-02-15 16:30:00', 'post_status' => 'publish', 'post_type' => 'post'],
        ],
        'wp_options' => [
            ['option_name' => 'siteurl', 'option_value' => 'http://myblog.com'],
            ['option_name' => 'home', 'option_value' => 'http://myblog.com'],
            ['option_name' => 'blogname', 'option_value' => 'My Blog'],
            ['option_name' => 'blogdescription', 'option_value' => 'Just another WordPress site'],
            ['option_name' => 'admin_email', 'option_value' => 'admin@myblog.com'],
            ['option_name' => 'siteurl', 'option_value' => 'http://myblog.com'],
            ['option_name' => 'db_version', 'option_value' => '58975'],
            ['option_name' => 'secret', 'option_value' => 'aB3xK9mP2nQ7vW4yL8jR5tZ1'],
        ],
        'wp_comments' => [
            ['comment_ID' => 1, 'comment_author' => 'Mr WordPress', 'comment_author_email' => '', 'comment_content' => 'Hi, this is a comment.', 'comment_post_ID' => 1, 'comment_date' => '2024-12-25 10:00:00'],
            ['comment_ID' => 2, 'comment_author' => 'Sarah', 'comment_author_email' => 'sarah@example.com', 'comment_content' => 'Great post!', 'comment_post_ID' => 2, 'comment_date' => '2024-12-26 15:00:00'],
        ],
    ];

    private $mysqlVersion = '8.0.36';
    private $phpVersion = '8.3.6';

    /**
     * Genera un error MySQL realista basado en el payload de inyección
     */
    public function generateError($payload, $uri = '') {
        $errors = [];

        // Error de sintaxis genérico
        $errors[] = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL ({$this->mysqlVersion}) server version for the right syntax to use near '" . $this->extractNear($payload) . "' at line 1";

        // Unknown column
        if (preg_match('/(\w+)\s*(?:=|IS)/i', $payload, $m)) {
            $errors[] = "Unknown column '{$m[1]}' in 'where clause'";
        }

        // Table doesn't exist
        if (preg_match('/FROM\s+(\w+)/i', $payload, $m)) {
            $errors[] = "Table 'wordpress.{$m[1]}' doesn't exist";
        }

        // Duplicate entry
        if (preg_match('/UNION/i', $payload)) {
            $errors[] = "The used SELECT statements have a different number of columns";
        }

        // Subquery returns more than 1 row
        $errors[] = "Subquery returns more than 1 row";

        // Seleccionar uno aleatoriamente para variedad
        $error = $errors[array_rand($errors)];

        // Formato de error WordPress/PHP realista
        if ($this->isAjaxRequest()) {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<div id='error'><p class='wpdberror'><strong>WordPress database error:</strong> [{$error}]<br />";
            echo "<code>" . htmlspecialchars($payload) . "</code></p></div>";
        } else {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<div class='wpdb-error'>";
            echo "<h1>Error establishing a database connection</h1>";
            echo "<p><strong>WordPress database error:</strong> {$error}</p>";
            echo "<p>This either means that the username and password information in your <code>wp-config.php</code> file is incorrect or we can't contact the database server at <code>localhost</code>.</p>";
            echo "</div>";
        }
    }

    /**
     * Genera respuesta para UNION SELECT - devuelve datos fake como si la inyección funcionara
     */
    public function generateUnionResponse($payload) {
        // Si parece que están sacando usuarios
        if (preg_match('/wp_users|user_login|user_pass|user_email/i', $payload)) {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<table border='1' cellpadding='4' cellspacing='0'>\n";
            echo "<tr><th>ID</th><th>user_login</th><th>user_pass</th><th>user_email</th></tr>\n";
            foreach ($this->fakeTables['wp_users'] as $user) {
                echo "<tr><td>{$user['ID']}</td><td>{$user['user_login']}</td><td>{$user['user_pass']}</td><td>{$user['user_email']}</td></tr>\n";
            }
            echo "</table>\n";
            return true;
        }

        // Si parece que están sacando posts
        if (preg_match('/wp_posts|post_title|post_content/i', $payload)) {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<table border='1' cellpadding='4' cellspacing='0'>\n";
            echo "<tr><th>ID</th><th>post_title</th><th>post_date</th><th>post_author</th></tr>\n";
            foreach ($this->fakeTables['wp_posts'] as $post) {
                echo "<tr><td>{$post['ID']}</td><td>{$post['post_title']}</td><td>{$post['post_date']}</td><td>{$post['post_author']}</td></tr>\n";
            }
            echo "</table>\n";
            return true;
        }

        // Si parece que están sacando options
        if (preg_match('/wp_options|option_name|option_value/i', $payload)) {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<table border='1' cellpadding='4' cellspacing='0'>\n";
            echo "<tr><th>option_name</th><th>option_value</th></tr>\n";
            foreach ($this->fakeTables['wp_options'] as $opt) {
                echo "<tr><td>{$opt['option_name']}</td><td>{$opt['option_value']}</td></tr>\n";
            }
            echo "</table>\n";
            return true;
        }

        // Generic: devolver error
        $this->generateError($payload);
        return true;
    }

    /**
     * Genera respuesta para time-based blind (SLEEP/BENCHMARK)
     */
    public function generateTimeBasedResponse($payload) {
        // Dormir realmente para que el atacante crea que funcionó
        if (preg_match('/SLEEP\s*\((\d+)\)/i', $payload, $m)) {
            sleep((int)$m[1]);
        } elseif (preg_match('/BENCHMARK\s*\((\d+)/i', $payload, $m)) {
            // Simular delay proporcional pero limitado
            usleep(min((int)$m[1], 5000000));
        }
        // Devolver página normal
        return false;
    }

    /**
     * Genera respuesta para error-based (EXTRACTVALUE/UPDATEXML)
     */
    public function generateErrorBasedResponse($payload) {
        $error = '';

        if (preg_match('/EXTRACTVALUE/i', $payload)) {
            // EXTRACTVALUE error format
            if (preg_match('/CONCAT\s*\(([^)]+)\)/i', $payload, $m)) {
                $data = $this->resolveConcat($m[1]);
                $error = "XPATH syntax error: '{$data}'";
            } else {
                $error = "XPATH syntax error: ''";
            }
        } elseif (preg_match('/UPDATEXML/i', $payload)) {
            if (preg_match('/CONCAT\s*\(([^)]+)\)/i', $payload, $m)) {
                $data = $this->resolveConcat($m[1]);
                $error = "XPATH syntax error: '{$data}'";
            } else {
                $error = "XPATH syntax error: ''";
            }
        }

        if ($error) {
            header('Content-Type: text/html; charset=UTF-8');
            echo "<strong>WordPress database error:</strong> [{$error}]<br />\n";
            echo "<code>" . htmlspecialchars($payload) . "</code>\n";
            return true;
        }

        return false;
    }

    /**
     * Responde a INFORMATION_SCHEMA queries
     */
    public function generateSchemaResponse($payload) {
        header('Content-Type: text/html; charset=UTF-8');

        if (preg_match('/TABLE_NAME|table_name/i', $payload)) {
            echo "<table border='1' cellpadding='3'>\n";
            echo "<tr><th>TABLE_NAME</th><th>TABLE_SCHEMA</th></tr>\n";
            $tables = ['wp_users', 'wp_usermeta', 'wp_posts', 'wp_postmeta', 'wp_comments', 'wp_commentmeta',
                       'wp_options', 'wp_terms', 'wp_term_taxonomy', 'wp_term_relationships',
                       'wp_links', 'wp_termmeta', 'wp_actionscheduler_actions', 'wp_actionscheduler_logs'];
            foreach ($tables as $t) {
                echo "<tr><td>{$t}</td><td>wordpress</td></tr>\n";
            }
            echo "</table>\n";
            return true;
        }

        if (preg_match('/COLUMN_NAME|column_name/i', $payload)) {
            echo "<table border='1' cellpadding='3'>\n";
            echo "<tr><th>COLUMN_NAME</th><th>DATA_TYPE</th><th>TABLE_NAME</th></tr>\n";
            $cols = [
                ['ID', 'bigint', 'wp_users'],
                ['user_login', 'varchar(60)', 'wp_users'],
                ['user_pass', 'varchar(255)', 'wp_users'],
                ['user_email', 'varchar(100)', 'wp_users'],
                ['user_registered', 'datetime', 'wp_users'],
                ['ID', 'bigint', 'wp_posts'],
                ['post_title', 'text', 'wp_posts'],
                ['post_content', 'longtext', 'wp_posts'],
                ['post_author', 'bigint', 'wp_posts'],
                ['option_name', 'varchar(191)', 'wp_options'],
                ['option_value', 'longtext', 'wp_options'],
            ];
            foreach ($cols as $c) {
                echo "<tr><td>{$c[0]}</td><td>{$c[1]}</td><td>{$c[2]}</td></tr>\n";
            }
            echo "</table>\n";
            return true;
        }

        return false;
    }

    /**
     * Detecta el tipo de SQLi y responde apropiadamente
     */
    public function respond($payload, $uri = '') {
        // Time-based blind
        if (preg_match('/SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY/i', $payload)) {
            return $this->generateTimeBasedResponse($payload);
        }

        // Error-based
        if (preg_match('/EXTRACTVALUE\s*\(|UPDATEXML\s*\(/i', $payload)) {
            return $this->generateErrorBasedResponse($payload);
        }

        // INFORMATION_SCHEMA
        if (preg_match('/INFORMATION_SCHEMA/i', $payload)) {
            return $this->generateSchemaResponse($payload);
        }

        // UNION-based
        if (preg_match('/UNION\s+(?:ALL\s+)?SELECT/i', $payload)) {
            return $this->generateUnionResponse($payload);
        }

        // Boolean-based - devolver contenido diferente según si parece true o false
        if (preg_match('/OR\s+[\d\']=.*?=/i', $payload) || preg_match('/AND\s+[\d\']=.*?=/i', $payload)) {
            // Devolver página normal (como si la condición fuera true)
            return false;
        }

        // Default: error SQL
        $this->generateError($payload, $uri);
        return true;
    }

    private function extractNear($payload) {
        // Extraer la parte relevante del payload para el error
        $payload = trim($payload);
        if (strlen($payload) > 60) {
            return substr($payload, 0, 60) . '...';
        }
        return $payload;
    }

    private function isAjaxRequest() {
        return (isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
                strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
    }

    private function resolveConcat($args) {
        // Simular CONCAT de MySQL con datos fake
        $args = explode(',', $args);
        $result = '';
        foreach ($args as $arg) {
            $arg = trim($arg);
            if (preg_match('/^0x([0-9a-f]+)/i', $arg, $m)) {
                $result .= hex2bin($m[1]);
            } elseif (preg_match('/^["\'](.*)["\']$/', $arg, $m)) {
                $result .= $m[1];
            } elseif (preg_match('/user_login/i', $arg)) {
                $result .= 'admin';
            } elseif (preg_match('/user_pass/i', $arg)) {
                $result .= '$P$BXbQ1MkTJqMzQ3NzRkMjY5MTIwMDAwMTIzNDU2Nzg';
            } elseif (preg_match('/user_email/i', $arg)) {
                $result .= 'admin@myblog.com';
            } elseif (preg_match('/version/i', $arg)) {
                $result .= $this->mysqlVersion;
            } elseif (preg_match('/database/i', $arg)) {
                $result .= 'wordpress';
            } elseif (preg_match('/user/i', $arg)) {
                $result .= 'wp_user@localhost';
            } elseif (preg_match('/@@/i', $arg)) {
                $result .= $this->mysqlVersion;
            } else {
                $result .= '0x' . bin2hex('data');
            }
        }
        return $result;
    }
}