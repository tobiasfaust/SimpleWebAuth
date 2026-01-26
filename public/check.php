<?php
$tz = getenv('TZ') ?: 'Europe/Berlin';
@date_default_timezone_set($tz);
$logFile = __DIR__ . '/../audit/' . date('Y-m-d') . '.log';
$secret = trim(file_get_contents(__DIR__.'/../secret.key'));

function render_login(string $target, ?string $message = null) {
    $msgHtml = $message ? '<div class="msg">'.htmlspecialchars($message, ENT_QUOTES, 'UTF-8').'</div>' : '';
    
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        .'<title>Anmeldung</title>'
        .'<link rel="stylesheet" href="style.css"></head>'
        .'<style>'
        .'</style></head><body><div class="center"><div class="card">'
        .'<h1>Login</h1>'
        .'<form method="post" action="">'
        .'<input type="hidden" name="return" value="'.htmlspecialchars($target, ENT_QUOTES, 'UTF-8').'">'
        .'<label for="username">Benutzername</label>'
        .'<input id="username" name="username" type="text" autocomplete="username" required>'
        .'<label for="password">Passwort</label>'
        .'<input id="password" name="password" type="password" autocomplete="current-password" required>'
        .'<div class="actions"><button type="submit">Senden</button></div>'
        .$msgHtml
        .'</form></div></div></body></html>';
}

function deny(string $logFile, string $reason) {
    file_put_contents(
        $logFile,
        date('c') . " ACCESS_DENIED {$reason} ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
        FILE_APPEND | LOCK_EX
    );
}

$target = isset($_GET['return']) ? $_GET['return'] : ($_POST['return'] ?? '/fhem/');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
        deny($logFile, 'invalid_credentials');
        render_login($target, 'Passwort falsch.');
        exit;
    }

    // Passwort-Hash aus JSON laden
    $userJsonPath = __DIR__ . '/../users/' . $username . '.json';
    $userData = is_file($userJsonPath) ? (json_decode(file_get_contents($userJsonPath), true) ?: []) : [];
    $hash = isset($userData['password_hash']) ? (string)$userData['password_hash'] : '';

    if (!$hash || !password_verify($password, $hash)) {
        deny($logFile, 'invalid_credentials');
        render_login($target, 'Passwort falsch.');
        exit;
    }

    // Ablaufzeit pro Nutzer aus users/<user>.json lesen
    $cookieExpSeconds = (int)($userData['cookie_exp_seconds'] ?? (60*60*24*30));
    if ($cookieExpSeconds < 60) { $cookieExpSeconds = 60; }
    if ($cookieExpSeconds > 60*60*24*365) { $cookieExpSeconds = 60*60*24*365; }

    // Nutzerstatus prüfen
    if (isset($userData['enabled']) && (int)$userData['enabled'] === 0) {
        deny($logFile, 'user_disabled user=' . $username);
        render_login($target, 'Konto ist deaktiviert.');
        exit;
    }

    $exp = time() + $cookieExpSeconds;
    $payload = ['user' => $username, 'exp' => $exp];
    $sig = hash_hmac('sha256', $username . '|' . $exp, $secret);
    $payload['sig'] = $sig;
    $session = base64_encode(json_encode($payload));

    setcookie('AUTH', $session, [
        'expires'  => $exp,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    file_put_contents(
        $logFile,
        date('c') . " LOGIN_GRANTED for user=" . $username . " ip=" . $_SERVER['REMOTE_ADDR'] . " target=" . $target . "\n",
        FILE_APPEND | LOCK_EX
    );

    header("Location: " . $target);
    exit;
}

// Cookie-Prüfung findet in validate_auth.php (RewriteMap) statt.
// Wird diese Seite aufgerufen, gilt der Cookie als ungültig/fehlend und wir zeigen die Login-Seite.
render_login($target);
exit;
?>
