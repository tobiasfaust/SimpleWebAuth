<?php
// setzt das persistente cookie 

$token = $_GET['token'] ?? '';
$file = __DIR__.'/../tokens/'.$token.'.json';
$logFile = __DIR__ . '/../audit/' . date('Y-m-d') . '.log';
$secret = trim(file_get_contents(__DIR__.'/../secret.key'));

if(!file_exists($file)){
    file_put_contents(
      $logFile,
      date('c') . " INVALID_TOKEN ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
      FILE_APPEND | LOCK_EX
    );
    http_response_code(403);
    exit('Ungültiger Magic-Link'.$file);
}
$data = json_decode(file_get_contents($file), true);



/* 
//Cookie setzen für 30 Tage
$session = base64_encode(json_encode([
    'user'=>$data['user'],
    'exp'=>time()+60*60*24*30
]));
setcookie('AUTH',$session,[
    'expires'=>time()+60*60*24*30,
    'path'=>'/',
    'secure'=>true,
    'httponly'=>true,
    'samesite'=>'Strict'
]);
*/

// Cookie-Ablauf aus users/<user>.json lesen
$usersDir = __DIR__ . '/../users';
$userJsonPath = $usersDir . '/' . $data['user'] . '.json';
$userJson = [];
if (is_file($userJsonPath)) {
    $userJson = json_decode(file_get_contents($userJsonPath), true) ?: [];
}
$cookieExpSeconds = (int)($userJson['cookie_exp_seconds'] ?? (60*60*24*30));
if ($cookieExpSeconds < 60) { $cookieExpSeconds = 60; }
if ($cookieExpSeconds > 60*60*24*365) { $cookieExpSeconds = 60*60*24*365; }

// Nutzerstatus prüfen (enabled)
$usersDir = __DIR__ . '/../users';
$userJsonPath = $usersDir . '/' . $data['user'] . '.json';
$userJson = is_file($userJsonPath) ? (json_decode(file_get_contents($userJsonPath), true) ?: []) : [];
if (isset($userJson['enabled']) && (int)$userJson['enabled'] === 0) {
     // Token einmalig verbrauchen, dann verweigern
     @unlink($file);
     file_put_contents(
          $logFile,
          date('c') . " LOGIN_DENIED_DISABLED user=" . $data['user'] . " ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
          FILE_APPEND | LOCK_EX
     );
     http_response_code(403);
     exit('Konto ist deaktiviert.');
}

$payload = [
    'user' => $data['user'],
    'exp'  => time() + $cookieExpSeconds
];

$signature = hash_hmac(
    'sha256',
    $payload['user'] . '|' . $payload['exp'],
    $secret
);

$payload['sig'] = $signature;

$session = base64_encode(json_encode($payload));

setcookie('AUTH', $session, [
    'expires'  => $payload['exp'],
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

// Token löschen (One-Time)
unlink($file);

// Audit log
file_put_contents(
    $logFile,
    date('c') . " LOGIN user=" . $data['user'] . " ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
    FILE_APPEND | LOCK_EX
);

// Kein Schreiben von last_login_at in die User-JSON; Login wird im Audit-Log erfasst

header("Location: /");
exit;
?>
