<?php
require_once __DIR__ . '/core/security.php';
ob_start(); // Taktik pembersihan output agar JSON murni
// This is a public, unauthenticated node directory API: it uses no cookies and
// returns no per-user data, so a wildcard origin does not enable CSRF or data
// theft here - CORS only constrains browsers, and nodes call it server-to-server
// where CORS does not apply at all. Restrict it if you want to limit which
// sites may read the directory from a browser.
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");
date_default_timezone_set('UTC');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); echo json_encode(['status' => 'error', 'message' => 'Use POST.']); exit;
}

$user_ip = relay_client_ip();

$raw_payload = file_get_contents('php://input');
$signal = json_decode($raw_payload, true);

$action = $signal['action'] ?? 'ping';

if (!$signal || empty($signal['planet_url'])) {
    http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Incomplete data.']); exit;
}

if ($action === 'ping' && empty($signal['station_name'])) {
    http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Station name required.']); exit;
}

$planet_url = rtrim(trim($signal['planet_url']), '/');

// This value is stored and then served to every client that reads the
// directory, so it has to be a real, externally reachable HTTPS address.
if (relay_url_is_safe($planet_url) !== true) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid planet_url.']);
    exit;
}

// Store the text as given and escape on OUTPUT. Escaping on input bakes the
// entities into the database, so every consumer then double-escapes and the
// stored value no longer round-trips.
$station_name = trim($signal['station_name'] ?? '');
$station_bio  = trim($signal['station_bio'] ?? '');

// [ V8.0.4 ] Software version reported by the station. This arrives from an
// unauthenticated endpoint, so it is treated as untrusted: length-capped and
// restricted to characters that can legitimately appear in a version string.
// Anything else becomes null, which the directory renders as "not reported"
// rather than echoing whatever was sent.
$version = null;
$version_raw = trim((string) ($signal['version'] ?? ''));
// Normalise a leading "v" (only when a digit follows, so an arbitrary string
// starting with the letter is not mangled). The directory renders this with a
// "v" of its own, so storing "v8.0.4" would display as "vv8.0.4"; and two
// stations reporting "v8.0.4" and "8.0.4" would otherwise compare as different
// versions in the fleet tally.
$version_raw = preg_replace('/^[vV](?=[0-9])/', '', $version_raw);
if ($version_raw !== ''
    && strlen($version_raw) <= 32
    && preg_match('/^[0-9A-Za-z][0-9A-Za-z._+-]*$/', $version_raw)) {
    $version = $version_raw;
}
if (mb_strlen($station_name) > 100) { $station_name = mb_substr($station_name, 0, 100); }
if (mb_strlen($station_bio) > 500)  { $station_bio  = mb_substr($station_bio, 0, 500); }

try {
    $db = new PDO('sqlite:' . __DIR__ . '/data/lighthouse.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 🛡️ [ INJEKSI ANTI TABRAKAN DATA (3 DETIK) ]
    $db->exec('PRAGMA busy_timeout = 3000;');

    // 🛡️ 1. RATE LIMIT
    // Shares relay_rate_limit() with the node's own inbox. The previous
    // implementation ran a full-table DELETE on every request and relied on an
    // upsert syntax that older SQLite builds do not support.
    if (!relay_rate_limit($db, 'lighthouse-register:' . $user_ip, 5, 60)) {
        ob_end_clean();
        http_response_code(429);
        echo json_encode(['status' => 'error', 'message' => 'Rate limit exceeded. Tactical shield engaged.']); exit;
    }


    // 🧹 2. THE SWEEPER (Hapus stasiun mati > 7 hari)
    $db->exec("DELETE FROM registry WHERE last_seen < datetime('now', '-7 days')");


    // 💥 3. THE KILL SIGNAL EXECUTION
    //
    // [ V8.0 ] THIS WAS UNAUTHENTICATED.
    // `kill` deletes a node from the public registry, and the only thing it
    // was checked against was the subject line in the request body. Any host
    // that knew the URL could POST {"action":"kill","planet_url":"<any node>"}
    // and remove somebody else's listing - a censorship and denial-of-service
    // primitive aimed at the directory itself.
    //
    // It now requires an admin token. The config file is deliberately NOT in
    // the repository: create lighthouse_config.php on the lighthouse
    // host and put a random string in it.
    //
    //     <?php define('LIGHTHOUSE_ADMIN_TOKEN', '<64 random hex chars>');
    //
    // If the file is missing, `kill` is DISABLED rather than left open. Nodes
    // that cannot delist simply stop pinging; the 7-day sweeper removes them.
    if ($action === 'kill') {
        $config_file = __DIR__ . '/lighthouse_config.php';
        $configured_token = null;
        if (file_exists($config_file)) {
            require_once $config_file;
            if (defined('LIGHTHOUSE_ADMIN_TOKEN')) {
                $configured_token = (string) LIGHTHOUSE_ADMIN_TOKEN;
            }
        }

        $supplied_token = (string) ($signal['admin_token'] ?? '');

        if ($configured_token === null || $configured_token === '') {
            error_log('[RELAY][SECURITY] kill refused: no LIGHTHOUSE_ADMIN_TOKEN configured');
            ob_end_clean();
            http_response_code(503);
            echo json_encode(['status' => 'error', 'message' => 'Node removal is not enabled on this lighthouse.']);
            exit;
        }

        if ($supplied_token === '' || !hash_equals($configured_token, $supplied_token)) {
            error_log('[RELAY][SECURITY] kill refused: bad or missing admin token from ' . $user_ip);
            ob_end_clean();
            http_response_code(403);
            echo json_encode(['status' => 'error', 'message' => '[ SHIELD REFLECTED ] Authorisation required.']);
            exit;
        }

        $stmt_kill = $db->prepare("DELETE FROM registry WHERE planet_url = :url");
        $stmt_kill->execute([':url' => $planet_url]);

        ob_end_clean();
        http_response_code(200);
        echo json_encode([
            'status' => 'success',
            'message' => 'Node vaporized from directory.',
            'url' => htmlspecialchars($planet_url, ENT_QUOTES, 'UTF-8'),
        ]);
        exit;
    }


    // 📡 4. NORMAL PING / REGISTRATION
    //
    // [ V8.0.4 ] The version column is written with COALESCE so that a station
    // older than v8.0.4 - which reports no version at all - cannot erase the
    // version a newer registration already recorded for the same URL during a
    // staged rollout. A missing value never overwrites a known one.
    $upsert_sql = "
        INSERT INTO registry (planet_url, station_name, station_bio, version, last_seen)
        VALUES (:url, :name, :bio, :version, CURRENT_TIMESTAMP)
        ON CONFLICT(planet_url) DO UPDATE SET
            station_name = excluded.station_name,
            station_bio = excluded.station_bio,
            version = COALESCE(excluded.version, registry.version),
            last_seen = CURRENT_TIMESTAMP
    ";

    $params = [':url' => $planet_url, ':name' => $station_name, ':bio' => $station_bio, ':version' => $version];

    // NOTE: prepare() is inside the try, not just execute(). PDO's SQLite driver
    // uses native prepares, so the statement is parsed - and the unknown column
    // detected - at prepare time. Wrapping only execute() looks correct and
    // silently never catches anything; that mistake was made and caught here
    // before shipping.
    try {
        $db->prepare($upsert_sql)->execute($params);
    } catch (PDOException $e) {
        // Self-healing migration. A hub installed before v8.0.4 has no version
        // column, and the lighthouse has no migration script of its own - the
        // setup file is deleted after install. Rather than require every hub
        // operator to re-run setup (which would refuse anyway, being a run-once
        // installer), the write path adds the column the first time it is
        // needed and retries. Steady state costs nothing: SQLite only raises
        // this on the very first registration after the upgrade.
        // SQLite words this differently depending on the statement, and both
        // have to be recognised or the migration silently never runs:
        //   INSERT ... -> "table registry has no column named version"
        //   SELECT ... -> "no such column: version"
        // (Verified against the actual driver messages rather than assumed.)
        $msg = $e->getMessage();
        $missing_column = stripos($msg, 'no such column') !== false
                       || stripos($msg, 'has no column named') !== false;
        if (!$missing_column) {
            throw $e;
        }
        $db->exec('ALTER TABLE registry ADD COLUMN version TEXT DEFAULT NULL');
        error_log('[RELAY] lighthouse registry upgraded: added version column');
        $db->prepare($upsert_sql)->execute($params);
    }

    ob_end_clean();
    http_response_code(200);
    echo json_encode([
        'status' => 'success',
        'message' => 'Docked.',
        'url' => htmlspecialchars($planet_url, ENT_QUOTES, 'UTF-8'),
    ]);

} catch (PDOException $e) {
    ob_end_clean();
    http_response_code(500);
    error_log('[RELAY] lighthouse register failed: ' . $e->getMessage());
    echo json_encode(['status' => 'error', 'message' => 'Database error.']);
}