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

    // [ V8.0.4 ] The version column is added on demand by api_register.php the
    // first time a station reports one, so a hub that has not been written to
    // since the upgrade still has the pre-v8.0.4 shape. Detect rather than
    // assume, and read without the column in that case: a directory that refuses
    // to render because it is one migration behind would be worse than one that
    // simply omits a field.
    $has_version = false;
    foreach ($db->query("PRAGMA table_info(registry)") as $col) {
        if (isset($col['name']) && $col['name'] === 'version') { $has_version = true; break; }
    }

    $columns = $has_version
        ? 'planet_url, station_name, station_bio, version, last_seen'
        : 'planet_url, station_name, station_bio, last_seen';

    $stmt = $db->query("SELECT $columns FROM registry ORDER BY last_seen DESC");
    $nodes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // [ V8.0.4 ] The newest version any station has reported. This is what the
    // landing page shows instead of a hand-typed release number - the point
    // being that the page states what is actually deployed across the fleet,
    // and never has to be edited again when a release goes out. Computed from
    // the raw values, before output escaping.
    $fleet_version = null;
    if ($has_version) {
        foreach ($nodes as $n) {
            $v = trim((string) ($n['version'] ?? ''));
            if ($v !== '' && ($fleet_version === null || version_compare($v, $fleet_version, '>'))) {
                $fleet_version = $v;
            }
        }
    }

    // Values are returned RAW. Do not escape HTML here.
    //
    // This is a JSON API: the transport carries data, and the renderer decides
    // how to encode it for its own context. HTML entities in a JSON payload are
    // wrong twice over - they corrupt the value for any non-HTML consumer, and
    // when the renderer escapes as well (as the landing page must, since these
    // fields arrive from a public unauthenticated endpoint) the entity surfaces
    // as literal text. That is what an apostrophe in a station bio became on the
    // landing page: "not somebody else&#039;s server".
    //
    // The previous revision escaped here while the comment above it warned that
    // escaping here would double-encode. It did.
    foreach ($nodes as &$node) {
        $node['planet_url']   = (string) $node['planet_url'];
        $node['station_name'] = (string) $node['station_name'];
        $node['station_bio']  = (string) ($node['station_bio'] ?? '');
        $node['version']      = isset($node['version']) && $node['version'] !== null
            ? (string) $node['version']
            : null;
    }
    unset($node);

    ob_end_clean();
    echo json_encode([
        'status' => 'success',
        'count' => count($nodes),
        'fleet_version' => $fleet_version,
        'timestamp' => date('Y-m-d H:i:s') . ' UTC',
        'nodes' => $nodes
    ], JSON_UNESCAPED_SLASHES);

} catch (PDOException $e) {
    ob_end_clean();
    http_response_code(500);
    error_log('[RELAY] lighthouse directory failed: ' . $e->getMessage());
    echo json_encode(['error' => 'Database error.']);
}