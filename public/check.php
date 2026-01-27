<?php
$tz = getenv('TZ') ?: 'Europe/Berlin';
@date_default_timezone_set($tz);
require_once __DIR__ . '/../common/utils.php';
$logFile = current_audit_log_path();
$secret = get_secret_key();

function render_login(string $target, ?string $message = null) {
    $msgHtml = $message ? '<div class="msg">'.htmlspecialchars($message, ENT_QUOTES, 'UTF-8').'</div>' : '';
    
    echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        .'<title>Anmeldung</title>'
        .'<link rel="stylesheet" href="style.css">'
        .'<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css"></head>'
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
        .'<div class="small-actions"><button type="submit" name="action" value="forgot" class="link-button" formnovalidate>Passwort vergessen?</button></div>'
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
    // Forgot password flow
    if (isset($_POST['action']) && $_POST['action'] === 'forgot') {
        $username = trim($_POST['username'] ?? '');
        if ($username === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
            render_login($target, 'Bitte zuerst gültigen Benutzernamen eingeben.');
            exit;
        }

        $userJsonPath = __DIR__ . '/../users/' . $username . '.json';
        if (!is_file($userJsonPath)) {
            // Privatsphäre: keine Differenzierung ob existiert
            render_login($target, 'Wenn ein Konto existiert, wurde eine E-Mail gesendet.');
            exit;
        }
        $userData = json_decode(file_get_contents($userJsonPath), true) ?: [];
        $to = (string)($userData['email'] ?? '');
        if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
            render_login($target, 'Kein gültige E-Mail hinterlegt. Bitte Admin kontaktieren.');
            exit;
        }

        // Create short-lived token (15 minutes)
        $token = bin2hex(random_bytes(16));
        $exp = time() + 15 * 60;
        $tokenFile = __DIR__ . '/../tokens/' . $token . '.json';
        $payload = [
            'user' => $username,
            'exp' => $exp,
            'kind' => 'password_reset'
        ];
        file_put_contents($tokenFile, json_encode($payload, JSON_UNESCAPED_SLASHES));
        file_put_contents($logFile, date('c') . ' PASSWORD_RESET_TOKEN_CREATED user=' . $username . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);

        // Abgelaufene Tokens entfernen (shared util)
        purge_expired_tokens(TOKENS_DIR);

        // Send email using settings (root-level settings.json)
        $settings = read_json_assoc(SETTINGS_PATH);
        $emailCfg = $settings['email'] ?? [];
        $resetLink = (isset($_SERVER['REQUEST_SCHEME']) ? $_SERVER['REQUEST_SCHEME'] : 'https') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/auth/passwordreset.php?token=' . urlencode($token);
        $subject = 'Passwort zurücksetzen';
        $textBody = "Sie erhalten diese E-Mail, weil die Funktion 'Passwort vergessen' auf SimpleWebAuth verwendet wurde.\n\n".
               "Der Link ist 15 Minuten gültig.\n\n".
               "Klicken Sie hier, um Ihr Passwort zurückzusetzen:\n" . $resetLink . "\n\n".
               "Wenn Sie diese Anfrage nicht gestellt haben, ignorieren Sie bitte diese E-Mail.";
        $htmlBody = '<!doctype html><html lang="de"><head><meta charset="utf-8">'
              . '</head><body style="font-family:Arial,Segoe UI,Helvetica,Arial,sans-serif;line-height:1.5;color:#222">'
              . '<h2 style="margin:0 0 12px;color:#0a246a">Passwort zurücksetzen</h2>'
              . '<p>Sie erhalten diese E-Mail, weil die Funktion <strong>„Passwort vergessen“</strong> auf SimpleWebAuth verwendet wurde.</p>'
              . '<p>Der Link ist <strong>15 Minuten</strong> gültig.</p>'
              . '<p style="margin:16px 0"><a href="' . htmlspecialchars($resetLink, ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;padding:10px 14px;background:#1f3b73;color:#fff;text-decoration:none;border-radius:6px">Passwort jetzt zurücksetzen</a></p>'
              . '<p>Alternativ können Sie diesen Link kopieren und in Ihren Browser einfügen:<br>'
              . '<span style="font-size:13px;color:#555">' . htmlspecialchars($resetLink, ENT_QUOTES, 'UTF-8') . '</span></p>'
              . '<hr style="border:none;border-top:1px solid #e5e5e5;margin:16px 0">'
              . '<p style="font-size:13px;color:#666">Wenn Sie diese Anfrage nicht gestellt haben, ignorieren Sie bitte diese E-Mail.</p>'
              . '</body></html>';

        $mailSent = false;
        require_composer_autoload();
        if (class_exists('PHPMailer\\PHPMailer\\PHPMailer')) {
            try {
            $mailer = new \PHPMailer\PHPMailer\PHPMailer(true);
                $mailer->isSMTP();
                $mailer->Host = (string)($emailCfg['smtp_host'] ?? '');
                $mailer->Port = (int)($emailCfg['smtp_port'] ?? 587);
                $sec = (string)($emailCfg['smtp_secure'] ?? 'tls');
                if ($sec === 'tls' || $sec === 'ssl') { $mailer->SMTPSecure = $sec; }
                $mailer->SMTPAuth = ((string)($emailCfg['smtp_username'] ?? '') !== '' || (string)($emailCfg['smtp_password'] ?? '') !== '');
                $mailer->Username = (string)($emailCfg['smtp_username'] ?? '');
                $mailer->Password = (string)($emailCfg['smtp_password'] ?? '');
                $mailer->CharSet = 'UTF-8';

                $from = (string)($emailCfg['from_address'] ?? '');
                if ($from === '' || !filter_var($from, FILTER_VALIDATE_EMAIL)) {
                    $from = filter_var((string)($emailCfg['smtp_username'] ?? ''), FILTER_VALIDATE_EMAIL) ? (string)$emailCfg['smtp_username'] : 'no-reply@localhost';
                }
                $fromName = (string)($emailCfg['from_name'] ?? 'SimpleWebAuth');
                $mailer->setFrom($from, $fromName);
                $mailer->addAddress($to);
                $mailer->Subject = $subject;
                $mailer->isHTML(true);
                $mailer->Body = $htmlBody;
                $mailer->AltBody = $textBody;
                $mailer->send();
                $mailSent = true;
            } catch (Throwable $ex) {
                file_put_contents($logFile, date('c') . ' PASSWORD_RESET_EMAIL_ERROR user=' . $username . ' err=' . str_replace("\n", ' ', $ex->getMessage()) . "\n", FILE_APPEND | LOCK_EX);
            }
        }

        if ($mailSent) {
            file_put_contents($logFile, date('c') . ' PASSWORD_RESET_EMAIL_SENT user=' . $username . "\n", FILE_APPEND | LOCK_EX);
            render_login($target, 'E-Mail gesendet. Bitte prüfen Sie Ihr Postfach.');
        } else {
            render_login($target, 'E-Mail konnte nicht gesendet werden. Bitte Admin kontaktieren.');
        }
        exit;
    }
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
