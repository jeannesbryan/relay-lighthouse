<?php
// ==========================================================================
// RELAY STATION: LIGHTHOUSE ADMIN CONFIGURATION (EXAMPLE)
// ==========================================================================
// Copy this file to lighthouse_config.php ON THE LIGHTHOUSE HOST ONLY, and
// put a real random value in it.
//
//   cp lighthouse_config.example.php lighthouse_config.php
//   php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'   # generate a token
//
// WHY THIS EXISTS
// The `kill` action of api_register.php deletes a node from the public
// directory. It used to be unauthenticated: any host could POST
//
//   {"action":"kill","planet_url":"<somebody else's node>"}
//
// and remove that node's listing - a censorship and denial-of-service
// primitive aimed at the directory itself. It now requires this token.
//
// FAIL-CLOSED: if lighthouse_config.php is absent, `kill` is DISABLED, not
// left open. A node that cannot delist itself simply stops pinging and is
// removed by the 7-day sweeper.
//
// The real file is gitignored. Never commit a token.

define('LIGHTHOUSE_ADMIN_TOKEN', 'change-me-generate-a-real-token');
