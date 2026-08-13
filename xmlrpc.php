<?php
/**
 * JesterTrap WP - Fake XML-RPC Server
 * Responde a system.listMethods, pingback.ping, wp.getUsersBlogs, etc.
 * Captura intentos de brute-force por XML-RPC y ataques pingback SSRF
 */
require_once __DIR__ . '/logger.php';

$log = new HoneypotLogger();

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$body = file_get_contents('php://input');

// Log siempre
$log->log('xmlrpc.request', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'POST',
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'ua' => $ua,
    'body' => mb_substr($body, 0, 2000),
]);

header('Content-Type: text/xml; charset=UTF-8');

// Si es GET, mostrar página fake de XML-RPC
if (($_SERVER['REQUEST_METHOD'] ?? 'POST') === 'GET') {
    echo '<?xml version="1.0" encoding="UTF-8"?>
<rsd version="1.0" xmlns="http://archipelago.phrasewise.com/rsd">
<service>
<engineName>WordPress</engineName>
<engineLink>https://wordpress.org/</engineLink>
<homePageLink>http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '</homePageLink>
<apis>
<api name="WordPress" blogID="1" preferred="true" apiLink="http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/xmlrpc.php" />
<api name="Movable Type" blogID="1" preferred="false" apiLink="http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/xmlrpc.php" />
<api name="MetaWeblog" blogID="1" preferred="false" apiLink="http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/xmlrpc.php" />
<api name="Blogger" blogID="1" preferred="false" apiLink="http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/xmlrpc.php" />
</apis>
</service>
</rsd>';
    exit;
}

// Parsear el método XML-RPC del body
$method = '';
if (preg_match('/<methodName>([^<]+)<\/methodName>/', $body, $m)) {
    $method = $m[1];
}

$log->log('xmlrpc.method', [
    'method_name' => $method,
    'ua' => $ua,
    'body' => mb_substr($body, 0, 2000),
]);

// Extraer credenciales si es intento de login
if (preg_match_all('/<string>([^<]*)<\/string>/', $body, $strings)) {
    $vals = $strings[1];
    if (count($vals) >= 2) {
        $log->log('xmlrpc.credentials', [
            'method_name' => $method,
            'param1' => $vals[0],
            'param2' => $vals[1],
            'extra_params' => array_slice($vals, 2),
            'ua' => $ua,
        ]);
    }
}

// Responder según el método
switch ($method) {
    case 'system.listMethods':
        echo '<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value>
<array>
<data>';
        $methods = [
            'system.listMethods', 'system.getCapabilities', 'system.multicall',
            'wp.getUsersBlogs', 'wp.login', 'wp.getProfile', 'wp.getOptions',
            'wp.getPosts', 'wp.getPost', 'wp.newPost', 'wp.editPost', 'wp.deletePost',
            'wp.getCategories', 'wp.getTags', 'wp.getMediaLibrary', 'wp.getMediaItem',
            'wp.uploadFile', 'wp.getCommentCount', 'wp.getPostStatusList',
            'wp.getPageStatusList', 'wp.getPageTemplates', 'wp.getOptions',
            'wp.setOptions', 'wp.getUsers', 'wp.getUser', 'wp.newUser', 'wp.editUser',
            'wp.deleteUser', 'wp.getTaxonomies', 'wp.getTaxonomy',
            'pingback.ping', 'pingback.extensions.getPingbacks',
            'mt.getRecentPostTitles', 'mt.getCategoryList', 'mt.getPostCategories',
            'mt.setPostCategories', 'mt.publishPost',
            'metaWeblog.getRecentPosts', 'metaWeblog.getPost', 'metaWeblog.newPost',
            'metaWeblog.editPost', 'metaWeblog.deletePost', 'metaWeblog.getCategories',
            'metaWeblog.getRecentPostTitles', 'metaWeblog.newMediaObject',
            'blogger.getUsersBlogs', 'blogger.getUserInfo', 'blogger.newPost',
            'blogger.editPost', 'blogger.deletePost',
        ];
        foreach ($methods as $m) {
            echo '<value><string>' . $m . '</string></value>';
        }
        echo '</data>
</array>
</value>
</param>
</params>
</methodResponse>';
        break;

    case 'system.getCapabilities':
        echo '<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value>
<struct>
<member>
<name>xmlrpc</name>
<value><struct>
<member><name>specUrl</name><value><string>http://www.xmlrpc.com/spec</string></value></member>
<member><name>specVersion</name><value><int>1</int></value></member>
</struct></value>
</member>
<member>
<name>faults_interop</name>
<value><struct>
<member><name>specUrl</name><value><string>http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php</string></value></member>
<member><name>specVersion</name><value><int>20010516</int></value></member>
</struct></value>
</member>
<member>
<name>system.multicall</name>
<value><struct>
<member><name>specUrl</name><value><string>http://www.xmlrpc.com/discuss/msgReader$1208</string></value></member>
<member><name>specVersion</name><value><int>1</int></value></member>
</struct></value>
</member>
<member>
<name>introspection</name>
<value><struct>
<member><name>specUrl</name><value><string>http://phpxmlrpc.sourceforge.net/doc-2/ch10.html</string></value></member>
<member><name>specVersion</name><value><int>2</int></value></member>
</struct></value>
</member>
</struct>
</value>
</param>
</params>
</methodResponse>';
        break;

    case 'wp.getUsersBlogs':
    case 'wp.login':
    case 'blogger.getUsersBlogs':
        // Respuesta de error: credenciales incorrectas (fomenta brute-force)
        echo '<?xml version="1.0"?>
<methodResponse>
<fault>
<value>
<struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct>
</value>
</fault>
</methodResponse>';
        break;

    case 'pingback.ping':
        // Loguear el target y source del pingback (SSRF potential)
        $source = '';
        $target = '';
        if (preg_match_all('/<string>([^<]*)<\/string>/', $body, $strings)) {
            $source = $strings[1][0] ?? '';
            $target = $strings[1][1] ?? '';
        }
        $log->log('xmlrpc.pingback', [
            'source_url' => $source,
            'target_url' => $target,
            'ua' => $ua,
        ]);
        echo '<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value><string>Pingback registered successfully.</string></value>
</param>
</params>
</methodResponse>';
        break;

    case 'pingback.extensions.getPingbacks':
        echo '<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value>
<array><data></data>
</array>
</value>
</param>
</params>
</methodResponse>';
        break;

    case 'system.multicall':
        // Log cada sub-llamada dentro del multicall
        $log->log('xmlrpc.multicall', [
            'body' => mb_substr($body, 0, 4000),
            'ua' => $ua,
        ]);
        echo '<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value>
<array>
<data>
<value>
<struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct>
</value>
</data>
</array>
</value>
</param>
</params>
</methodResponse>';
        break;

    default:
        // Respuesta genérica de error para métodos no reconocidos
        echo '<?xml version="1.0"?>
<methodResponse>
<fault>
<value>
<struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct>
</value>
</fault>
</methodResponse>';
        break;
}