<?php
$tz = getenv('TZ') ?: 'Europe/Berlin';
@date_default_timezone_set($tz);
require_once __DIR__ . '/../common/utils.php';
$logFile = current_audit_log_path();

// password_complexity_ok is provided by common/utils.php

function render_form(string $token, ?string $message = null) {
    $msgHtml = $message ? '<div class="msg">'.htmlspecialchars($message, ENT_QUOTES, 'UTF-8').'</div>' : '';
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        .'<title>Passwort zurücksetzen</title>'
        .'<link rel="stylesheet" href="style.css">'
        .'<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css"></head>'
        .'<body><div class="center"><div class="card">'
        .'<h1>Passwort zurücksetzen</h1>'
        .'<form method="post" action="">'
        .'<input type="hidden" name="token" value="'.htmlspecialchars($token, ENT_QUOTES, 'UTF-8').'">'
        .'<label for="password">Neues Passwort</label>'
        .'<input id="password" name="password" type="password" autocomplete="new-password" required>'
        .'<label for="password2">Neues Passwort (Wiederholung)</label>'
        .'<input id="password2" name="password2" type="password" autocomplete="new-password" required>'
        .'<div class="actions"><button type="submit">Speichern</button></div>'
        .$msgHtml
        .'</form></div></div></body></html>';
}

function render_message(string $text) {
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        .'<title>Passwort zurücksetzen</title>'
        .'<link rel="stylesheet" href="style.css">'
        .'<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css"></head>'
        .'<body><div class="center"><div class="card">'
        .'<h1>Passwort zurücksetzen</h1>'
        .'<p style="text-align:center">'.htmlspecialchars($text, ENT_QUOTES, 'UTF-8').'</p>'
        .'</div></div></body></html>';
}

$token = trim($_GET['token'] ?? ($_POST['token'] ?? ''));
if ($token === '' || !preg_match('/^[a-f0-9]{32}$/', $token)) {
    render_message('Ungültiger Link.');
    exit;
}

$tokenFile = __DIR__ . '/../tokens/' . $token . '.json';
if (!is_file($tokenFile)) {
    render_message('Token nicht gefunden oder bereits verwendet.');
    exit;
}
$payload = json_decode(file_get_contents($tokenFile), true) ?: [];
if (($payload['kind'] ?? 'password_reset') !== 'password_reset') {
    render_message('Ungültiger Token-Typ.');
    exit;
}
$user = (string)($payload['user'] ?? '');
$exp = (int)($payload['exp'] ?? 0);
if ($user === '' || time() > $exp) {
    @unlink($tokenFile);
    render_message('Token abgelaufen.');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = (string)($_POST['password'] ?? '');
    $password2 = (string)($_POST['password2'] ?? '');
    if ($password === '' || $password2 === '' || $password !== $password2) {
        render_form($token, 'Passwörter stimmen nicht überein.');
        exit;
    }
    if (!password_complexity_ok($password)) {
        render_form($token, 'Passwort ist zu schwach (mind. 3 von: Groß-/Kleinschreibung, Ziffern, Sonderzeichen).');
        exit;
    }
    $userFile = __DIR__ . '/../users/' . $user . '.json';
    if (!is_file($userFile)) {
        render_message('Nutzerkonto nicht gefunden.');
        exit;
    }
    $data = json_decode(file_get_contents($userFile), true) ?: [];
    $data['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
    $data['updated_at'] = time();
    $data['last_pw_generated_at'] = $data['updated_at'];
    // atomic write
    $tmp = $userFile . '.tmp';
    if (file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) !== false && rename($tmp, $userFile)) {
        @unlink($tokenFile);
        file_put_contents($logFile, date('c') . ' PASSWORD_RESET_DONE user=' . $user . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
        render_message('Passwort geändert. Sie können sich nun anmelden.');
        exit;
    } else {
        render_form($token, 'Speichern fehlgeschlagen. Bitte erneut versuchen.');
        exit;
    }
}

render_form($token);
exit;
