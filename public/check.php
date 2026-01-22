<?php
$logFile = __DIR__ . '/../audit/' . date('Y-m-d') . '.log';
$secret = trim(file_get_contents(__DIR__.'/../secret.key'));

function deny(string $logFile, string $reason) {
    file_put_contents(
        $logFile,
        date('c') . " ACCESS_DENIED {$reason} ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
        FILE_APPEND | LOCK_EX
    );
    http_response_code(401);
    exit('Nicht angemeldet - '.$reason);
}

// 1. eigentlicher Check
if(!isset($_COOKIE['AUTH'])){
   deny($logFile, 'not authenticated');
}

$data = json_decode(base64_decode($_COOKIE['AUTH'] ?? ''), true);

if (!$data || !isset($data['user'], $data['exp'], $data['sig'])) {
    deny($logFile, 'malformed_cookie');
}

if ($data['exp'] < time()) {
    deny($logFile, 'expired_cookie');
}

$expectedSig = hash_hmac(
    'sha256',
    $data['user'] . '|' . $data['exp'],
    $secret
);

if (!hash_equals($expectedSig, $data['sig'])) {
    deny($logFile, 'invalid_signature');
}


// 2. Token ist gültig!
// Hinweis: Kein zusätzliches "OK"-Cookie mehr nötig.
// Die Apache-Konfiguration prüft ab jetzt das AUTH-Cookie per RewriteMap
// bei jeder Anfrage und lässt nur dann zum Backend durch.

// 3. Zurückleiten an die ursprüngliche Anfrage
// Wenn kein 'return' Parameter da ist, einfach zu /fhem
$target = isset($_GET['return']) ? $_GET['return'] : '/fhem/';
header("Location: " . $target);
exit;

?>
