<?php
// ==========================================
// 🛠️ THE LIGHTHOUSE PROTOCOL: DISPOSABLE SETUP
// Eksekusi skrip ini SEKALI SAJA di browser, lalu HAPUS berkasnya.
// ==========================================
header('Content-Type: text/plain');

$db_dir = __DIR__ . '/data';
$db_file = $db_dir . '/lighthouse.sqlite';

// [ V8.0 ] Run-once guard.
// This script was reachable by anyone who guessed the path, at any time, and
// each request would (re)create the directory and database. It is an
// installation step, not an endpoint. Once the database exists there is
// nothing left to set up, so it now refuses and tells the operator to delete
// the file - which is what the original comment already asked for but nothing
// enforced.
if (file_exists($db_file)) {
    http_response_code(409);
    echo "[ STOP ] Lighthouse sudah terpasang.\n\n";
    echo "Berkas ini HANYA untuk pemasangan awal dan sekarang harus DIHAPUS:\n";
    echo "  rm " . __FILE__ . "\n";
    exit;
}

// 1. Ciptakan Ruang Penyimpanan
if (!is_dir($db_dir)) {
    if (mkdir($db_dir, 0755, true)) {
        echo "[ OK ] Folder 'data/' berhasil diciptakan.\n";
    } else {
        die("[ GAGAL ] Tidak bisa membuat folder 'data/'. Cek hak akses (chmod).\n");
    }
}

try {
    // 2. Bangun Reaktor SQLite
    $db = new PDO('sqlite:' . $db_dir . '/lighthouse.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 3. Aktifkan Mode Ngebut (WAL)
    $db->exec('PRAGMA journal_mode = WAL;');
    echo "[ OK ] Mode WAL (Write-Ahead Logging) diaktifkan.\n";

    // 4. Cor Coran Tabel Utama
    // [ V8.0.4 ] `version` is what each station reports about the software it
    // is running. The lighthouse is the only place that sees every station, so
    // it is the only place where "what is actually deployed out there" can be
    // known - and it is known without any station contacting a third party.
    // Nullable: a station older than v8.0.4 reports nothing.
    $db->exec("CREATE TABLE IF NOT EXISTS registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        planet_url TEXT UNIQUE NOT NULL,
        station_name TEXT NOT NULL,
        station_bio TEXT,
        version TEXT DEFAULT NULL,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Protect the directory the same way data/ is protected: the registry is
    // runtime state and must not be downloadable. Written for both Apache
    // 2.2 and 2.4 syntax.
    $htaccess = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
              . "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
    @file_put_contents($db_dir . '/.htaccess', $htaccess);

    echo "[ OK ] Tabel 'registry' siap menerima pendaratan sinyal.\n";
    echo "[ OK ] Akses langsung ke folder data/ diblokir.\n\n";
    echo "[ 🚨 PERHATIAN ] Pembangunan selesai. Harap SEGERA HAPUS berkas setup_lighthouse.php ini dari peladen Anda demi keamanan!";

} catch (PDOException $e) {
    // Never print the driver message: it carries the database path.
    error_log('[RELAY] lighthouse setup failed: ' . $e->getMessage());
    echo "[ ERROR ] Reaktor gagal dibangun. Periksa log peladen.";
}