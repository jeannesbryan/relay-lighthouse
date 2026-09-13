<?php
// ==========================================================================
// 🛡️ RELAY STATION 8.0 — SECURITY BOOTSTRAP
// ==========================================================================
// Single place where session policy, CSRF, client-IP resolution, outbound-URL
// validation and TLS-enforced HTTP are defined. Every endpoint includes this
// file instead of re-implementing the same checks inline.
//
// WHY THIS FILE EXISTS: the v7.3 codebase repeated the same session_start(),
// the same auth check, the same IP extraction and the same curl setup in about
// ten places. They had drifted apart, and the drifting copies were the ones
// with the holes. Centralising means a fix lands once and applies everywhere.
//
// This file adds no features. It only closes holes.
// ==========================================================================

if (defined('RELAY_SECURITY_LOADED')) {
    return;
}
define('RELAY_SECURITY_LOADED', true);

// --------------------------------------------------------------------------
// CONFIGURATION
// --------------------------------------------------------------------------

// Trust CF-Connecting-IP only when the immediate peer is genuinely Cloudflare.
// An unauthenticated client can send that header freely; it only means anything
// when REMOTE_ADDR is a Cloudflare edge node.
define('RELAY_TRUST_CLOUDFLARE', true);

// Authoritative list, mirrored from https://www.cloudflare.com/ips-v4 and
// /ips-v6. Re-check these if Cloudflare announces a range change.
const RELAY_CLOUDFLARE_V4 = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];
const RELAY_CLOUDFLARE_V6 = [
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// Outbound federation is HTTPS-only and limited to these ports.
const RELAY_ALLOWED_OUTBOUND_PORTS = [443];

// Session idle / absolute lifetimes, in seconds.
const RELAY_SESSION_IDLE_TTL     = 3600;    // 1 hour without activity
const RELAY_SESSION_ABSOLUTE_TTL = 43200;   // 12 hours since login, no matter what

// --------------------------------------------------------------------------
// ERROR HANDLING — never echo internals
// --------------------------------------------------------------------------

/**
 * Log the real error, show the caller something generic.
 *
 * v7.3 did `die("... " . $e->getMessage())` in six places, which printed PDO
 * errors (including the database path and sometimes SQL) straight to the
 * browser. Those details are useful to exactly one audience.
 */
function relay_fail($public_message, $log_detail = null, $http_code = 400, $as_json = false)
{
    if ($log_detail !== null) {
        error_log('[RELAY][SECURITY] ' . $log_detail);
    }
    if (!headers_sent()) {
        http_response_code($http_code);
    }
    if ($as_json) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => $public_message]);
    } else {
        echo htmlspecialchars($public_message, ENT_QUOTES, 'UTF-8');
    }
    exit;
}

/** Boolean test for "am I at an /api_ endpoint", used to pick JSON vs HTML. */
function relay_is_api_request()
{
    return strpos($_SERVER['SCRIPT_NAME'] ?? '', 'api_') !== false;
}

// --------------------------------------------------------------------------
// TRANSPORT — is this connection actually HTTPS?
// --------------------------------------------------------------------------

/**
 * Determine HTTPS from signals we are willing to trust.
 *
 * v7.3 trusted X-Forwarded-Proto and X-Forwarded-SSL unconditionally. Both are
 * request headers, so anyone talking plain HTTP could set
 * `X-Forwarded-Proto: https` and convince ssl_shield.php the link was encrypted
 * — silently disabling the entire HTTPS enforcement. Forwarded headers are now
 * only consulted when the peer is a Cloudflare edge address.
 */
function relay_is_https()
{
    if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (!empty($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
        return true;
    }

    if (RELAY_TRUST_CLOUDFLARE) {
        $peer = relay_normalize_ip($_SERVER['REMOTE_ADDR'] ?? '');
        if ($peer !== '' && relay_is_cloudflare_ip($peer)) {
            if (!empty($_SERVER['HTTP_CF_VISITOR'])) {
                $visitor = json_decode($_SERVER['HTTP_CF_VISITOR'], true);
                if (isset($visitor['scheme']) && strtolower($visitor['scheme']) === 'https') {
                    return true;
                }
            }
            if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])
                && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
                return true;
            }
        }
    }

    return false;
}

// --------------------------------------------------------------------------
// IP RESOLUTION
// --------------------------------------------------------------------------

/** Strip a port or IPv6 brackets from an address string. */
function relay_normalize_ip($ip)
{
    $ip = trim((string) $ip);
    if ($ip === '') {
        return '';
    }
    if (preg_match('/^\[(.+)\](?::\d+)?$/', $ip, $m)) {
        return trim($m[1]);
    }
    if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $ip, $m)) {
        return $m[1];
    }
    // ::ffff:1.2.3.4 -> 1.2.3.4
    if (stripos($ip, '::ffff:') === 0 && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return substr($ip, 7);
    }
    return $ip;
}

/** CIDR containment that handles both IPv4 and IPv6 correctly. */
function relay_ip_in_cidr($ip, $cidr)
{
    $slash = strpos($cidr, '/');
    if ($slash === false) {
        return false;
    }
    $subnet = substr($cidr, 0, $slash);
    $bits   = (int) substr($cidr, $slash + 1);

    $ip_bin  = @inet_pton($ip);
    $sub_bin = @inet_pton($subnet);
    if ($ip_bin === false || $sub_bin === false || strlen($ip_bin) !== strlen($sub_bin)) {
        return false;
    }
    $max_bits = strlen($ip_bin) * 8;
    if ($bits < 0 || $bits > $max_bits) {
        return false;
    }

    $whole = intdiv($bits, 8);
    if ($whole > 0 && substr($ip_bin, 0, $whole) !== substr($sub_bin, 0, $whole)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem > 0) {
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        if ((ord($ip_bin[$whole]) & $mask) !== (ord($sub_bin[$whole]) & $mask)) {
            return false;
        }
    }
    return true;
}

function relay_is_cloudflare_ip($ip)
{
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    $ranges = (strpos($ip, ':') !== false) ? RELAY_CLOUDFLARE_V6 : RELAY_CLOUDFLARE_V4;
    foreach ($ranges as $cidr) {
        if (relay_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * The client IP, resolved defensively.
 *
 * v7.3 read HTTP_CF_CONNECTING_IP then HTTP_X_FORWARDED_FOR and used the value
 * as if it were trustworthy. Because both are plain request headers, an
 * attacker could rotate them per request and defeat BOTH the 15-minute
 * brute-force lockout and the rate limiter — two Critical controls reduced to
 * decoration. Here the default is REMOTE_ADDR, and forwarded headers are only
 * honoured when the peer really is a Cloudflare edge node.
 */
function relay_client_ip()
{
    $remote = relay_normalize_ip($_SERVER['REMOTE_ADDR'] ?? '');

    if (RELAY_TRUST_CLOUDFLARE && $remote !== '' && relay_is_cloudflare_ip($remote)) {
        $cf = relay_normalize_ip($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '');
        if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) {
            return $cf;
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Left-most entry is the original client.
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $first = relay_normalize_ip($parts[0]);
            if ($first !== '' && filter_var($first, FILTER_VALIDATE_IP)) {
                return $first;
            }
        }
    }

    return ($remote !== '' && filter_var($remote, FILTER_VALIDATE_IP)) ? $remote : '0.0.0.0';
}

// --------------------------------------------------------------------------
// SESSION
// --------------------------------------------------------------------------

/**
 * Start the session with hardened parameters.
 *
 * Must run before any output. use_strict_mode rejects a session id the server
 * never issued, which closes session fixation.
 */
function relay_session_start()
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    if (relay_is_https()) {
        ini_set('session.cookie_secure', '1');
    }

    session_name('RELAY_SID');
    session_start();

    // Absolute lifetime: a stolen session dies on schedule regardless of use.
    if (!isset($_SESSION['relay_created_at'])) {
        $_SESSION['relay_created_at'] = time();
    } elseif (time() - (int) $_SESSION['relay_created_at'] > RELAY_SESSION_ABSOLUTE_TTL) {
        relay_session_destroy();
        relay_session_start();
        $_SESSION['relay_created_at'] = time();
    }

    // Idle lifetime.
    if (isset($_SESSION['relay_last_seen'])
        && time() - (int) $_SESSION['relay_last_seen'] > RELAY_SESSION_IDLE_TTL) {
        relay_session_destroy();
        relay_session_start();
        $_SESSION['relay_created_at'] = time();
    }
    $_SESSION['relay_last_seen'] = time();
}

/** Issue a new session id. Called on every privilege change (login). */
function relay_session_regenerate()
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

function relay_session_destroy()
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], (bool) $p['secure'], (bool) $p['httponly']);
    }
    session_destroy();
}

// --------------------------------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------------------------------

function relay_is_authenticated()
{
    return isset($_SESSION['relay_auth']) && $_SESSION['relay_auth'] === true;
}

/**
 * The one auth guard. Every protected endpoint calls this first, before it
 * touches input, the database or the filesystem.
 */
function relay_require_auth($as_json = null)
{
    if ($as_json === null) {
        $as_json = relay_is_api_request();
    }
    if (!relay_is_authenticated()) {
        relay_fail('[ ACCESS DENIED ] Authentication required.', 'unauthenticated access attempt', 403, $as_json);
    }
}

// --------------------------------------------------------------------------
// CSRF
// --------------------------------------------------------------------------

/** Per-session token, generated once. */
function relay_csrf_token()
{
    if (empty($_SESSION['relay_csrf']) || !is_string($_SESSION['relay_csrf'])) {
        $_SESSION['relay_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['relay_csrf'];
}

/** Hidden input for a form. */
function relay_csrf_field()
{
    return '<input type="hidden" name="relay_csrf" value="' . htmlspecialchars(relay_csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

/** Constant-time compare; never leaks length through timing. */
function relay_csrf_verify($token)
{
    if (!is_string($token) || $token === '') {
        return false;
    }
    $known = $_SESSION['relay_csrf'] ?? '';
    if (!is_string($known) || $known === '') {
        return false;
    }
    return hash_equals($known, $token);
}

/**
 * Enforce POST + a valid CSRF token.
 *
 * Every state-changing action goes through this. GET must never mutate.
 */
function relay_require_post_and_csrf($as_json = null)
{
    if ($as_json === null) {
        $as_json = relay_is_api_request();
    }
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($method !== 'POST') {
        relay_fail('[ REJECTED ] This action requires POST.', "method $method rejected on state-changing action", 405, $as_json);
    }
    $token = $_POST['relay_csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!relay_csrf_verify($token)) {
        relay_fail('[ REJECTED ] Invalid or missing security token.', 'CSRF token mismatch', 403, $as_json);
    }
}

/** Reject anything that is not POST (for endpoints with no session/CSRF state). */
function relay_require_post($as_json = null)
{
    if ($as_json === null) {
        $as_json = relay_is_api_request();
    }
    if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        relay_fail('[ REJECTED ] This endpoint accepts POST only.', 'non-POST request rejected', 405, $as_json);
    }
}

// --------------------------------------------------------------------------
// OUTBOUND URL VALIDATION (SSRF)
// --------------------------------------------------------------------------

/**
 * Is this IP address safe to connect out to?
 *
 * Blocks loopback, private, link-local (which includes the 169.254.169.254
 * cloud metadata endpoint), CGNAT, documentation, multicast and reserved
 * ranges, for both address families.
 */
function relay_ip_is_public($ip)
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    // filter_var covers the IPv4 private and reserved blocks.
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }

    if (strpos($ip, ':') !== false) {
        $blocked = [
            '::1/128',          // loopback
            '::/128',           // unspecified
            'fc00::/7',         // unique local
            'fe80::/10',        // link-local
            'ff00::/8',         // multicast
            '2001:db8::/32',    // documentation
            '2002::/16',        // 6to4, can embed a private v4
        ];
        foreach ($blocked as $cidr) {
            if (relay_ip_in_cidr($ip, $cidr)) {
                return false;
            }
        }
        return true;
    }

    $long = ip2long($ip);
    if ($long === false) {
        return false;
    }
    $blocked_v4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
        '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
        '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
        '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    ];
    foreach ($blocked_v4 as $cidr) {
        if (relay_ip_in_cidr($ip, $cidr)) {
            return false;
        }
    }
    return true;
}

/**
 * Validate a node URL before it is handed to curl.
 *
 * @return true|string  true when safe, otherwise a short reason (safe to log).
 *
 * Checks, in order: scheme is HTTPS, no embedded credentials, host present
 * and not a literal blocked address, port in the allowlist, and every address
 * the hostname resolves to is publicly routable. The resolved addresses are
 * returned via $resolved so the caller can PIN them, closing the DNS-rebinding
 * window between this check and the actual connection.
 */
function relay_url_is_safe($url, &$resolved = null)
{
    $resolved = [];

    if (!is_string($url) || trim($url) === '') {
        return 'empty url';
    }
    $url = trim($url);

    $parts = parse_url($url);
    if ($parts === false || !is_array($parts)) {
        return 'unparseable url';
    }

    $scheme = strtolower($parts['scheme'] ?? '');
    if ($scheme !== 'https') {
        return 'scheme must be https';
    }
    if (isset($parts['user']) || isset($parts['pass'])) {
        return 'credentials not allowed in url';
    }

    $host = $parts['host'] ?? '';
    if ($host === '') {
        return 'missing host';
    }
    // Normalise the brackets parse_url leaves on IPv6 literals.
    $host = trim($host, '[]');

    $port = $parts['port'] ?? 443;
    if (!in_array((int) $port, RELAY_ALLOWED_OUTBOUND_PORTS, true)) {
        return 'port not allowed';
    }

    // Host is a literal address?
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!relay_ip_is_public($host)) {
            return 'host address is not publicly routable';
        }
        $resolved = [$host];
        return true;
    }

    // Reject the obvious internal names before we even do DNS.
    $lower = strtolower($host);
    if ($lower === 'localhost' || substr($lower, -6) === '.local' || substr($lower, -8) === '.internal') {
        return 'host resolves to an internal name';
    }

    $ips = [];
    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (is_array($records)) {
        foreach ($records as $r) {
            if (!empty($r['ip'])) {
                $ips[] = $r['ip'];
            } elseif (!empty($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }
    }
    if (!$ips) {
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) {
            $ips = $v4;
        }
    }
    if (!$ips) {
        return 'host did not resolve';
    }

    foreach ($ips as $ip) {
        if (!relay_ip_is_public($ip)) {
            return 'host resolves to a non-public address';
        }
    }

    $resolved = array_values(array_unique($ips));
    return true;
}

/**
 * Same validation, but refuses to continue on failure.
 * Use where a bad URL means the whole request is invalid.
 */
function relay_assert_safe_url($url, $as_json = null)
{
    $resolved = [];
    $verdict = relay_url_is_safe($url, $resolved);
    if ($verdict !== true) {
        relay_fail('[ REJECTED ] Node address is not permitted.', 'outbound url rejected: ' . $verdict, 400, $as_json);
    }
    return $resolved;
}

// --------------------------------------------------------------------------
// OUTBOUND HTTP (curl with TLS verification, no redirects, pinned DNS)
// --------------------------------------------------------------------------

/**
 * Build a curl handle for one outbound HTTPS request.
 *
 * This is the only place in the codebase that should call curl_init() for a
 * node URL. It enforces:
 *   - certificate AND hostname verification (v7.3 disabled the former in five
 *     places, which makes every TLS guarantee in the app cosmetic)
 *   - HTTPS only, at the protocol level
 *   - no redirect following (a redirect is an SSRF bypass: validation happens
 *     on the first URL, curl would then follow to anywhere)
 *   - a bounded timeout
 *   - the DNS result that was validated, pinned via CURLOPT_RESOLVE
 *
 * @param string   $url      already validated by relay_assert_safe_url()
 * @param string[] $resolved addresses returned by the validation step
 */
function relay_curl_init($url, array $resolved = [])
{
    $ch = curl_init($url);

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_USERAGENT, 'RelayStation/8.0');

    if (defined('CURLOPT_PROTOCOLS_STR')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'https');
    } elseif (defined('CURLOPT_PROTOCOLS')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    }

    // Pin the address we validated, so DNS cannot be re-pointed between the
    // safety check and the connection (DNS rebinding).
    if ($resolved) {
        $parts = parse_url($url);
        $host  = trim($parts['host'] ?? '', '[]');
        $port  = (int) ($parts['port'] ?? 443);
        $pins  = [];
        foreach ($resolved as $ip) {
            $pin = $ip;
            if (strpos($ip, ':') !== false) {
                $pin = '[' . $ip . ']';
            }
            $pins[] = $host . ':' . $port . ':' . $pin;
        }
        if ($pins) {
            curl_setopt($ch, CURLOPT_RESOLVE, $pins);
        }
    }

    return $ch;
}

/**
 * Validate, then perform a GET with full verification.
 *
 * @return array{ok:bool, status:int, body:string|false, error:string}
 */
function relay_http_get($url, $timeout = 10)
{
    $resolved = [];
    $verdict = relay_url_is_safe($url, $resolved);
    if ($verdict !== true) {
        return ['ok' => false, 'status' => 0, 'body' => false, 'error' => $verdict];
    }

    $ch = relay_curl_init($url, $resolved);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    $body   = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err    = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'status' => $status, 'body' => false, 'error' => $err ?: 'request failed'];
    }
    return ['ok' => ($status >= 200 && $status < 300), 'status' => $status, 'body' => $body, 'error' => ''];
}

/**
 * Validate a node URL and return a ready curl handle, or null if it is unsafe.
 *
 * Node URLs arrive from two places: operator input (add_planet, transmitter)
 * and the stored Star Chart. Both are re-validated here at the moment of use.
 * Re-validating stored URLs is not redundant - a hostname that resolved to a
 * public address when it was saved can later resolve to a private one, and a
 * check that lives at the point of use cannot be omitted by a future caller.
 *
 * Callers must treat null as "skip this node", not as "try anyway".
 */
function relay_node_curl($url)
{
    $resolved = [];
    if (relay_url_is_safe($url, $resolved) !== true) {
        error_log('[RELAY][SECURITY] refused outbound request to: ' . $url);
        return null;
    }
    return relay_curl_init($url, $resolved);
}

// --------------------------------------------------------------------------
// SECURITY HEADERS
// --------------------------------------------------------------------------

function relay_send_security_headers()
{
    if (headers_sent()) {
        return;
    }
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('X-Frame-Options: DENY');
    header('Cross-Origin-Resource-Policy: same-origin');
    // Deliberately no HSTS here: it is a long-lived commitment and belongs in
    // the web-server config next to the HTTPS redirect, not in application code.
}

// --------------------------------------------------------------------------
// UPLOAD VALIDATION
// --------------------------------------------------------------------------

define('RELAY_MAX_MEDIA_BYTES', 5 * 1024 * 1024);   // 5 MB per file
define('RELAY_MAX_AUDIO_BYTES', 10 * 1024 * 1024);  // 10 MB per voice note

/**
 * Identify a file from its leading bytes.
 *
 * Returns a canonical type ('webp', 'webm', 'ogg', 'm4a') or null. The
 * extension written to disk is derived from THIS, never from the type the
 * caller declared - the declared type in a data: URL is attacker-controlled
 * and only describes intent.
 */
function relay_sniff_media_type($data)
{
    if (!is_string($data) || strlen($data) < 12) {
        return null;
    }
    $head = substr($data, 0, 16);

    // WebP: "RIFF" .... "WEBP"
    if (substr($head, 0, 4) === 'RIFF' && substr($head, 8, 4) === 'WEBP') {
        return 'webp';
    }
    // Matroska / WebM: EBML header 1A 45 DF A3
    if (substr($head, 0, 4) === "\x1A\x45\xDF\xA3") {
        return 'webm';
    }
    // Ogg: "OggS"
    if (substr($head, 0, 4) === 'OggS') {
        return 'ogg';
    }
    // ISO base media (m4a/mp4): "....ftyp" at offset 4
    if (substr($head, 4, 4) === 'ftyp') {
        return 'm4a';
    }
    return null;
}

/**
 * Decode and validate a data: URL body, or return null.
 *
 * v7.3 wrote whatever base64 it was handed straight into media/ with an
 * extension fixed to .webp - no size limit and no content check. It could not
 * be turned into PHP execution because the extension is not .php, but it was
 * an unauthenticated arbitrary-file-write primitive inside the web root, at
 * unbounded size, with the served content-type taken from the request.
 *
 * @return array{data:string,ext:string}|null
 */
function relay_decode_media_data_url($value, $max_bytes)
{
    if (!is_string($value) || $value === '') {
        return null;
    }
    if (strpos($value, ',') === false) {
        return null;
    }
    list(, $encoded) = explode(',', $value, 2);

    // Reject whitespace and anything that is not base64 before decoding, so a
    // multi-megabyte string of junk is not decoded just to be discarded.
    $encoded = str_replace(' ', '+', trim($encoded));
    if ($encoded === '' || strlen($encoded) > (int) ceil($max_bytes * 4 / 3) + 64) {
        return null;
    }
    if (!preg_match('~^[A-Za-z0-9+/]+={0,2}$~', $encoded)) {
        return null;
    }

    $data = base64_decode($encoded, true);
    if ($data === false || $data === '') {
        return null;
    }
    if (strlen($data) > $max_bytes) {
        return null;
    }

    $ext = relay_sniff_media_type($data);
    if ($ext === null) {
        return null;
    }

    return ['data' => $data, 'ext' => $ext];
}

/**
 * Validate a real multipart upload.
 *
 * Forces is_uploaded_file() (so a path cannot be smuggled in via $_FILES) and
 * re-derives the extension from the file's own magic bytes.
 *
 * @return array{tmp:string,ext:string,size:int}|null
 */
function relay_validate_upload($file, $max_bytes)
{
    if (!is_array($file) || !isset($file['tmp_name'], $file['error'], $file['size'])) {
        return null;
    }
    if ((int) $file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    if ((int) $file['size'] > $max_bytes || (int) $file['size'] <= 0) {
        return null;
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return null;
    }

    $head = (string) @file_get_contents($file['tmp_name'], false, null, 0, 16);
    $ext = relay_sniff_media_type($head);
    if ($ext === null) {
        return null;
    }

    return ['tmp' => $file['tmp_name'], 'ext' => $ext, 'size' => (int) $file['size']];
}

// --------------------------------------------------------------------------
// RATE LIMITING
// --------------------------------------------------------------------------

/**
 * Fixed-window rate limiter backed by SQLite.
 *
 * Returns true when the caller is within budget, false when it has been
 * exceeded. The key is a caller-supplied bucket string, so the same counter
 * serves different endpoints independently.
 *
 * DESIGN NOTE - why this replaced the v7.3 limiter in api_inbox.php:
 * that version ran `DELETE FROM rate_limits WHERE timestamp <= ...` on EVERY
 * inbound request and then inserted one row per request. That is a full-table
 * scan-and-delete plus a write, per signal, on a database that is also serving
 * reads - write amplification directly on the hot path, and the table grows
 * once per request inside the window. Keeping one row per bucket per window
 * removes both: the update is a single indexed row, and pruning is
 * opportunistic and bounded so it can never dominate a request.
 */
function relay_rate_limit(PDO $db, $bucket, $limit, $window_seconds)
{
    $now = time();
    $window_start = $now - ($now % max(1, (int) $window_seconds));
    $bucket = (string) $bucket;

    $db->exec("CREATE TABLE IF NOT EXISTS relay_rate_limits (
        bucket TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        hits INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket, window_start)
    )");

    // Read-modify-write inside a transaction. SQLite serialises writers, so
    // this is race-free without needing an upsert syntax that older SQLite
    // builds may not support.
    $db->beginTransaction();
    try {
        $sel = $db->prepare("SELECT hits FROM relay_rate_limits WHERE bucket = :b AND window_start = :w");
        $sel->execute([':b' => $bucket, ':w' => $window_start]);
        $hits = $sel->fetchColumn();

        if ($hits === false) {
            $db->prepare("INSERT INTO relay_rate_limits (bucket, window_start, hits) VALUES (:b, :w, 1)")
               ->execute([':b' => $bucket, ':w' => $window_start]);
            $hits = 1;
        } else {
            $hits = (int) $hits + 1;
            $db->prepare("UPDATE relay_rate_limits SET hits = :h WHERE bucket = :b AND window_start = :w")
               ->execute([':h' => $hits, ':b' => $bucket, ':w' => $window_start]);
        }
        $db->commit();
    } catch (Exception $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        error_log('[RELAY] rate limit update failed: ' . $e->getMessage());
        // Fail open on an internal error: a broken counter must not become an
        // outage. The request still passes every other check.
        return true;
    }

    // Prune occasionally, and only rows far outside any active window.
    if (random_int(1, 50) === 1) {
        try {
            $db->prepare("DELETE FROM relay_rate_limits WHERE window_start < :cutoff")
               ->execute([':cutoff' => $now - ((int) $window_seconds * 10)]);
        } catch (Exception $e) {
            error_log('[RELAY] rate limit prune failed: ' . $e->getMessage());
        }
    }

    return $hits <= $limit;
}

// --------------------------------------------------------------------------
// INPUT VALIDATION HELPERS
// --------------------------------------------------------------------------

/**
 * Whitelist a value against known-good options.
 *
 * v7.3 used strip_tags()/trim() on the `visibility` field, which is not a
 * validation strategy: it removed markup but accepted any string, so any value
 * outside the intended set flowed on into storage and comparisons.
 */
function relay_require_enum($value, array $allowed, $default = null)
{
    if (is_string($value) && in_array($value, $allowed, true)) {
        return $value;
    }
    return $default;
}

/** The only values the `visibility` column may take. */
const RELAY_VISIBILITY_VALUES = [
    'public', 'direct', 'sonar_pulse', 'ack_receipt', 'scorched_earth', 'global_purge', 'resonance',
];
