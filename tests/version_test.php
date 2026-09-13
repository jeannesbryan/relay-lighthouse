<?php
// Version reporting test: does the hub accept, sanitise and store the version a
// station reports, and does it tally the fleet version correctly?
//
// WHY THIS EXISTS: the hub had no tests at all, and v8.0.4 gave it real logic:
// input validation on an unauthenticated endpoint, a self-healing schema
// migration for hubs installed before the column existed, and a fleet tally.
//
// Two mistakes were already made and caught while building that, and both are
// pinned here so they cannot come back:
//
//   1. The self-healing migration matched only SQLite's "no such column" text.
//      That is the wording for SELECT; an INSERT says "table X has no column
//      named Y". The migration looked correct and silently never ran.
//   2. PDO's SQLite driver uses native prepares, so an unknown column is raised
//      by prepare(), not execute(). A try block around execute() alone catches
//      nothing.
//
// Runs entirely in a temporary directory with its own database and its own
// php -S instances. Nothing here touches a live hub.
//
// Run: php tests/version_test.php

$ROOT = dirname(__DIR__);

$pass = 0; $fail = 0;
function check($label, $cond, $extra = '')
{
    global $pass, $fail;
    if ($cond) { $pass++; echo "  PASS  $label\n"; }
    else { $fail++; echo "  FAIL  $label" . ($extra !== '' ? "   [$extra]" : '') . "\n"; }
}

$tmp = sys_get_temp_dir() . '/relay_hub_' . getmypid();
$portLegacy = 18011;
$portFresh  = 18012;

// ---------------------------------------------------------------------------
// Two hubs: one with the v8.0.4 schema, one with the schema as it was before
// (no version column). The legacy one is what a hub already running in the
// wild looks like.
// ---------------------------------------------------------------------------
function buildHub($dir, $withVersion)
{
    @mkdir($dir . '/data', 0777, true);
    $dbFile = $dir . '/data/lighthouse.sqlite';
    foreach ([$dbFile, $dbFile . '-wal', $dbFile . '-shm'] as $f) { @unlink($f); }

    $db = new PDO('sqlite:' . $dbFile);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $cols = "id INTEGER PRIMARY KEY AUTOINCREMENT, planet_url TEXT UNIQUE NOT NULL,
             station_name TEXT NOT NULL, station_bio TEXT,"
          . ($withVersion ? " version TEXT DEFAULT NULL," : "")
          . " last_seen DATETIME DEFAULT CURRENT_TIMESTAMP";
    $db->exec("CREATE TABLE IF NOT EXISTS registry ($cols)");
    if (!$withVersion) {
        $db->exec("INSERT INTO registry (planet_url, station_name, station_bio)
                   VALUES ('https://pre-existing.example/relay','PREEXISTING','there before the upgrade')");
    }
    $db = null;
}

function rrmdir($path)
{
    if (is_dir($path)) {
        foreach (scandir($path) as $e) {
            if ($e === '.' || $e === '..') { continue; }
            rrmdir($path . '/' . $e);
        }
        @rmdir($path);
    } else {
        @unlink($path);
    }
}

rrmdir($tmp);
foreach ([['fresh', true], ['legacy', false]] as [$sub, $withVersion]) {
    buildHub("$tmp/$sub", $withVersion);
    // copy the hub into the test dir
    $src = $ROOT;
    foreach (['api_register.php', 'api_directory.php'] as $f) {
        copy("$src/$f", "$tmp/$sub/$f");
    }
    @mkdir("$tmp/$sub/core", 0777, true);
    copy("$src/core/security.php", "$tmp/$sub/core/security.php");
}

// curl rather than file_get_contents: a hard --max-time per call, and the HTTP
// status comes back with the body so a failure says *why* (429 from the rate
// limiter, 500 from the endpoint) instead of surfacing as a missing row. The
// built-in server is single-threaded, so one slow request delays the next -
// discovering that the hard way is what produced this helper.
function httpJson($url, $method = 'GET', $body = null)
{
    $cmd = 'curl -sS -o - -w "\n%{http_code}" --max-time 8 -X ' . escapeshellarg($method);
    if ($body !== null) {
        $cmd .= ' -H ' . escapeshellarg('Content-Type: application/json')
              . ' -d ' . escapeshellarg($body);
    }
    $cmd .= ' ' . escapeshellarg($url) . ' 2>/dev/null';

    $out = (string) shell_exec($cmd);
    $nl = strrpos($out, "\n");
    if ($nl === false) { return ['__http' => 0]; }

    $decoded = json_decode(substr($out, 0, $nl), true);
    if (!is_array($decoded)) { $decoded = []; }
    $decoded['__http'] = (int) substr($out, $nl + 1);
    return $decoded;
}

// Servers are started detached and stopped by pattern at the end. popen()/pclose()
// was tried first and is the wrong tool here: pclose blocks until the child
// exits, and the child here is a server that does not.
function startServer($dir, $port)
{
    $cmd = sprintf('php -S 127.0.0.1:%d -t %s > /dev/null 2>&1 &', $port, escapeshellarg($dir));
    exec($cmd);
    usleep(900000);
}

startServer("$tmp/legacy", $portLegacy);
startServer("$tmp/fresh", $portFresh);

// Read a stored value through a short-lived connection. Every read closes its
// cursor and drops its handle: PDO's SQLite driver keeps a shared lock while a
// result set is still open, and a lingering one from this process made the
// server's next write fail as a database error. That is a test artifact, not a
// product bug - the same requests succeed when replayed with curl - but it made
// a passing implementation look broken, which is worse than a red test.
function storedVersion($dbFile, $stationName)
{
    $db = new PDO('sqlite:' . $dbFile);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA busy_timeout = 3000;');
    $st = $db->prepare('SELECT version FROM registry WHERE station_name = ?');
    $st->execute([$stationName]);
    $value = $st->fetchColumn();
    $st->closeCursor();
    $db = null;
    return $value;
}

$regL = "http://127.0.0.1:$portLegacy/api_register.php";
$dirL = "http://127.0.0.1:$portLegacy/api_directory.php";
$regF = "http://127.0.0.1:$portFresh/api_register.php";
$dirF = "http://127.0.0.1:$portFresh/api_directory.php";

function clearRateLimit($dbFile)
{
    try {
        $d = new PDO('sqlite:' . $dbFile);
        @$d->exec('DELETE FROM relay_rate_limits');
    } catch (Exception $e) { /* table may not exist yet */ }
}

// ---------------------------------------------------------------------------
echo "== legacy hub: read path before the column exists ==\n";
$d = httpJson($dirL);
check('directory still responds on a hub without the version column',
      is_array($d) && ($d['status'] ?? '') === 'success', json_encode($d));
check('fleet_version is null rather than a crash', array_key_exists('fleet_version', $d) && $d['fleet_version'] === null);

// ---------------------------------------------------------------------------
echo "\n== legacy hub: self-healing migration ==\n";
clearRateLimit("$tmp/legacy/data/lighthouse.sqlite");
$r = httpJson($regL, 'POST', json_encode([
    'action' => 'ping', 'planet_url' => 'https://jeannesbryan.my.id/relay',
    'station_name' => 'MYNODE', 'station_bio' => 'test', 'version' => '8.0.4',
]));
check('registration succeeds on a pre-v8.0.4 hub', ($r['status'] ?? '') === 'success', json_encode($r));

function registryColumns($dbFile)
{
    $db = new PDO('sqlite:' . $dbFile);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $cols = [];
    $st = $db->query('PRAGMA table_info(registry)');
    foreach ($st as $c) { $cols[] = $c['name']; }
    $st->closeCursor();
    $db = null;
    return $cols;
}

$cols = registryColumns("$tmp/legacy/data/lighthouse.sqlite");
check('the version column was added on demand', in_array('version', $cols, true), implode(',', $cols));

$d = httpJson($dirL);
check('the reported version is stored and served',
      ($d['fleet_version'] ?? null) === '8.0.4', json_encode($d['fleet_version'] ?? null));
check('the pre-existing row survived the migration',
      count(array_filter($d['nodes'], fn($n) => $n['station_name'] === 'PREEXISTING')) === 1);

// ---------------------------------------------------------------------------
echo "\n== a station that reports no version must not erase a known one ==\n";
clearRateLimit("$tmp/legacy/data/lighthouse.sqlite");
httpJson($regL, 'POST', json_encode([
    'action' => 'ping', 'planet_url' => 'https://jeannesbryan.my.id/relay',
    'station_name' => 'MYNODE', 'station_bio' => 'older build re-registered',
]));
$d = httpJson($dirL);
$mine = null;
foreach ($d['nodes'] as $n) { if ($n['station_name'] === 'MYNODE') { $mine = $n; } }
check('COALESCE kept the version a newer registration recorded',
      $mine !== null && $mine['version'] === '8.0.4', json_encode($mine['version'] ?? null));
check('the rest of the row was still updated',
      $mine !== null && strpos($mine['station_bio'], 'older build') === 0);

// ---------------------------------------------------------------------------
echo "\n== untrusted version input ==\n";
$cases = [
    ['<script>alert(1)</script>', null, 'markup is rejected'],
    ['x; DROP TABLE registry;--',  null, 'an injection attempt is rejected'],
    [str_repeat('A', 60),          null, 'an over-long value is rejected'],
    ['v8.0.5',                  '8.0.5', 'a leading v is normalised away'],
    ['8.0.5-rc1',             '8.0.5-rc1', 'a pre-release suffix is allowed'],
];
$i = 0;
foreach ($cases as [$input, $expected, $label]) {
    $i++;
    clearRateLimit("$tmp/legacy/data/lighthouse.sqlite");
    $resp = httpJson($regL, 'POST', json_encode([
        'action' => 'ping', 'planet_url' => "https://github.com/hubtest$i/relay",
        'station_name' => "CASE$i", 'station_bio' => 'x', 'version' => $input,
    ]));

    $stored = storedVersion("$tmp/legacy/data/lighthouse.sqlite", "CASE$i");

    $ok = ($expected === null) ? ($stored === null) : ($stored === $expected);
    // Say what the endpoint answered when this fails, so a rate-limit or a
    // crash is not mistaken for a validation bug.
    $detail = 'stored=' . var_export($stored, true)
            . ' http=' . ($resp['__http'] ?? '?')
            . ' said=' . ($resp['status'] ?? '-') . '/' . ($resp['message'] ?? '-');
    check($label, $ok, $detail);
}

// ---------------------------------------------------------------------------
echo "\n== the fleet tally takes the highest reported version ==\n";
clearRateLimit("$tmp/fresh/data/lighthouse.sqlite");
// NODE_OLD sends no version at all - the shape a station older than v8.0.4
// still sends. It must be listed like any other, with a null version.
foreach ([['https://github.com/a/relay', 'NODE_A', '8.0.3'],
          ['https://github.com/b/relay', 'NODE_B', '8.0.5'],
          ['https://github.com/c/relay', 'NODE_C', '8.0.4'],
          ['https://github.com/d/relay', 'NODE_OLD', null]] as [$url, $name, $ver]) {
    $payload = [
        'action' => 'ping', 'planet_url' => $url,
        'station_name' => $name, 'station_bio' => 'x',
    ];
    if ($ver !== null) { $payload['version'] = $ver; }
    httpJson($regF, 'POST', json_encode($payload));
    clearRateLimit("$tmp/fresh/data/lighthouse.sqlite");
}
$d = httpJson($dirF);
check('four stations registered', ($d['count'] ?? 0) === 4, (string) ($d['count'] ?? 0));
check('fleet_version is the highest, not the newest or the first',
      ($d['fleet_version'] ?? null) === '8.0.5', json_encode($d['fleet_version'] ?? null));

// ---------------------------------------------------------------------------
echo "\n== a node older than the field is still listed ==\n";
$old = null;
foreach ($d['nodes'] as $n) { if ($n['station_name'] === 'NODE_OLD') { $old = $n; } }
check('a station that reports no version still appears in the directory', $old !== null);
check('its version is null, not an empty string', $old !== null && $old['version'] === null,
      json_encode($old['version'] ?? 'missing'));

// ---------------------------------------------------------------------------
// Stop both servers by pattern, then confirm they are gone. A leftover server
// would hold the port for the next run.
exec("pkill -f " . escapeshellarg("php -S 127.0.0.1:$portLegacy"));
exec("pkill -f " . escapeshellarg("php -S 127.0.0.1:$portFresh"));
usleep(300000);

// Bracket the port's last digit in the pattern: pgrep matches against full
// command lines, and the shell running this very pgrep has the pattern text in
// its own command line, so an un-bracketed pattern counts itself.
$leftover = (int) trim((string) shell_exec(
    "pgrep -fc 'php -S 127.0.0.1:180[1]' 2>/dev/null"
));
check('no test server left running', $leftover === 0, "still running: $leftover");

rrmdir($tmp);
check('the test directory was cleaned up', !is_dir($tmp), $tmp);

echo "\n==================================================================\n";
printf(" HUB: %d passed, %d failed\n", $pass, $fail);
echo "==================================================================\n";
exit($fail === 0 ? 0 : 1);
