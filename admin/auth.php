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

$payload = [
    'user' => $data['user'],
    'exp'  => time() + 60*60*24*30
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
header("Location: /");
exit;
?>
