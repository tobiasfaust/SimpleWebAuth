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

/*
$data = json_decode(base64_decode($_COOKIE['AUTH']), true);

if(!$data || $data['exp'] < time()){
    file_put_contents(
        $logFile,
        date('c') . " ACCESS_DENIED expired_cookie ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
        FILE_APPEND | LOCK_EX
    );
    http_response_code(401);
    exit('Session abgelaufen');
}
*/

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


// 2. ERWEITERUNG: Token ist gültig!
// Wir setzen ein kurzlebiges Cookie (Session-Cookie), das Apache als "Türöffner" dient.
// Wichtig: Der Pfad muss "/" oder "/fhem" sein.
setcookie("FHEM_OK", "true", 0, "/", "", false, true);

// 3. Zurückleiten an die ursprüngliche Anfrage
// Wenn kein 'return' Parameter da ist, einfach zu /fhem
$target = isset($_GET['return']) ? $_GET['return'] : '/fhem/';
header("Location: " . $target);
exit;

?>
