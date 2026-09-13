<?php
require_once __DIR__ . '/core/security.php';
ob_start(); // Pembersihan output
// Public read-only directory: no cookies, no per-user data, so a wildcard
// origin carries no CSRF or data-theft risk here.
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");
date_default_timezone_set('UTC');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

$db_path = __DIR__ . '/data/lighthouse.sqlite';

if (!file_exists($db_path)) {
    ob_end_clean();
    echo json_encode(['status' => 'success', 'count' => 0, 'nodes' => [], 'message' => 'Empty']);
    exit;
}

try {
    $db = new PDO('sqlite:' . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 🛡️ [ INJEKSI ANTI TABRAKAN DATA (3 DETIK) ]
    $db->exec('PRAGMA busy_timeout = 3000;');

    // [ V8.0 ] The sweeper used to run here, so a GET request mutated the
    // database. Read paths should not write: it made every directory read a
    // write transaction (with its own lock contention), and it let an
    // unauthenticated client drive unlimited DELETE work by polling. The sweep
    // now happens on registration, in api_register.php, where the endpoint is
    // already rate-limited and already writing.

    $stmt = $db->query("SELECT planet_url, station_name, station_bio, last_seen FROM registry ORDER BY last_seen DESC");
    $nodes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Escape on output. Values are stored raw now, so whoever renders them
    // controls the context; escaping here would double-encode.
    foreach ($nodes as &$node) {
        $node['planet_url']   = htmlspecialchars((string) $node['planet_url'], ENT_QUOTES, 'UTF-8');
        $node['station_name'] = htmlspecialchars((string) $node['station_name'], ENT_QUOTES, 'UTF-8');
        $node['station_bio']  = htmlspecialchars((string) $node['station_bio'], ENT_QUOTES, 'UTF-8');
    }
    unset($node);

    ob_end_clean();
    echo json_encode([
        'status' => 'success',
        'count' => count($nodes),
        'timestamp' => date('Y-m-d H:i:s') . ' UTC',
        'nodes' => $nodes
    ], JSON_UNESCAPED_SLASHES);

} catch (PDOException $e) {
    ob_end_clean();
    http_response_code(500);
    error_log('[RELAY] lighthouse directory failed: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error.']);
}