<?php
// Admin Settings: PHPMailer SMTP configuration stored in admin/settings.json

$settingsFile = __DIR__ . '/settings.json';
$logFile = __DIR__ . '/../audit/' . date('Y-m-d') . '.log';

// Helper: read/write JSON safe
function read_json_assoc(string $file): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}
function write_json_assoc(string $file, array $data): bool {
    $tmp = $file . '.tmp';
    $payload = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($payload === false) return false;
    $ok = file_put_contents($tmp, $payload, LOCK_EX) !== false;
    if ($ok) {
        return rename($tmp, $file);
    }
    return false;
}

// Minimal auth banner (same as other admin pages)
$loggedUser = null;
if (!empty($_COOKIE['AUTH'])) {
    $decoded = base64_decode($_COOKIE['AUTH'], true);
    if ($decoded !== false) {
        $data = json_decode($decoded, true);
        if (is_array($data) && !empty($data['user']) && preg_match('/^[A-Za-z0-9._-]+$/', $data['user'])) {
            $loggedUser = $data['user'];
        }
    }
}

// Load existing settings
$settings = read_json_assoc($settingsFile);
if (!isset($settings['email'])) {
    $settings['email'] = [];
}
$email = $settings['email'];

// Defaults
$emailDefaults = [
    'smtp_host' => '',
    'smtp_port' => 587,
    'smtp_secure' => 'tls', // tls|ssl|none
    'smtp_username' => '',
    'smtp_password' => '', // stored as cleartext for now; PHPMailer typically requires plain password
    'from_address' => '',
    'from_name' => ''
];
$email = array_merge($emailDefaults, array_intersect_key($email, $emailDefaults));

$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'save_email';
    if ($action === 'save_email') {
        // Save settings from form
        $smtp_host = trim($_POST['smtp_host'] ?? '');
        $smtp_port = (int)($_POST['smtp_port'] ?? 587);
        $smtp_secure = trim($_POST['smtp_secure'] ?? 'tls');
        $smtp_username = trim($_POST['smtp_username'] ?? '');
        $smtp_password = (string)($_POST['smtp_password'] ?? '');
        $from_address = trim($_POST['from_address'] ?? '');
        $from_name = trim($_POST['from_name'] ?? '');

        if ($smtp_port <= 0 || $smtp_port > 65535) {
            $error = 'Ungültiger Port.';
        } elseif ($smtp_secure !== 'tls' && $smtp_secure !== 'ssl' && $smtp_secure !== 'none') {
            $error = 'Ungültige Verschlüsselung (tls, ssl oder none).';
        } elseif ($from_address !== '' && !filter_var($from_address, FILTER_VALIDATE_EMAIL)) {
            $error = 'From-Adresse ist keine gültige E-Mail.';
        }

        // PHPMailer requires the plain SMTP password; hashes cannot authenticate.
        if ($error === null) {
            $settings['email'] = [
                'smtp_host' => $smtp_host,
                'smtp_port' => $smtp_port,
                'smtp_secure' => $smtp_secure,
                'smtp_username' => $smtp_username,
                'smtp_password' => $smtp_password,
                'from_address' => $from_address,
                'from_name' => $from_name
            ];
            if (write_json_assoc($settingsFile, $settings)) {
                $message = 'Einstellungen gespeichert.';
                @file_put_contents($logFile, date('c') . ' SETTINGS_UPDATED category=email ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
                $email = $settings['email'];
            } else {
                $error = 'Konnte Einstellungen nicht speichern.';
            }
        }
    } elseif ($action === 'test_email') {
        // Send test email using current settings (from disk to ensure consistency)
        $test_to = trim($_POST['test_to'] ?? '');
        if ($test_to === '' || !filter_var($test_to, FILTER_VALIDATE_EMAIL)) {
            $error = 'Bitte eine gültige Empfänger-Adresse angeben.';
        } else {
            // Reload fresh settings from disk
            $settings = read_json_assoc($settingsFile);
            $email = array_merge($emailDefaults, $settings['email'] ?? []);

            // Try to load PHPMailer via Composer autoload
            $autoloads = [__DIR__ . '/../../vendor/autoload.php', __DIR__ . '/vendor/autoload.php'];
            $autoloadLoaded = false;
            foreach ($autoloads as $autoload) {
                if (is_file($autoload)) { require_once $autoload; $autoloadLoaded = true; break; }
            }
            if (!$autoloadLoaded || !class_exists('PHPMailer\\PHPMailer\\PHPMailer')) {
                $error = 'PHPMailer ist nicht installiert. Bitte via Composer installieren: composer require phpmailer/phpmailer';
            } else {
                try {
                    $mailer = new \PHPMailer\PHPMailer\PHPMailer(true);
                    $mailer->isSMTP();
                    $mailer->Host = (string)$email['smtp_host'];
                    $mailer->Port = (int)$email['smtp_port'];
                    $sec = (string)$email['smtp_secure'];
                    if ($sec === 'tls' || $sec === 'ssl') { $mailer->SMTPSecure = $sec; }
                    $mailer->SMTPAuth = ($email['smtp_username'] !== '' || $email['smtp_password'] !== '');
                    $mailer->Username = (string)$email['smtp_username'];
                    $mailer->Password = (string)$email['smtp_password'];
                    $mailer->CharSet = 'UTF-8';

                    $from = (string)$email['from_address'];
                    if ($from === '' || !filter_var($from, FILTER_VALIDATE_EMAIL)) {
                        // fallback: if username looks like email, use it; else default
                        $from = filter_var((string)$email['smtp_username'], FILTER_VALIDATE_EMAIL) ? (string)$email['smtp_username'] : 'no-reply@localhost';
                    }
                    $fromName = (string)$email['from_name'];
                    if ($fromName === '') { $fromName = 'SimpleWebAuth'; }
                    $mailer->setFrom($from, $fromName);
                    $mailer->addAddress($test_to);
                    $mailer->Subject = 'Test-E-Mail von SimpleWebAuth';
                    $mailer->Body = "Dies ist eine Test-E-Mail.\n\nZeit: " . date('c');
                    $mailer->AltBody = 'Dies ist eine Test-E-Mail.';

                    $mailer->send();
                    $message = 'Test-E-Mail wurde versendet an ' . htmlspecialchars($test_to, ENT_QUOTES, 'UTF-8') . '.';
                    @file_put_contents($logFile, date('c') . ' SETTINGS_TEST_EMAIL ok to=' . $test_to . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
                } catch (Throwable $ex) {
                    $error = 'Senden fehlgeschlagen: ' . $ex->getMessage();
                    @file_put_contents($logFile, date('c') . ' SETTINGS_TEST_EMAIL error=' . str_replace("\n", ' ', $ex->getMessage()) . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
                }
            }
        }
    }
}

?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Einstellungen</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <?php if ($loggedUser): ?><div class="welcome">Willkommen <?= htmlspecialchars($loggedUser, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <h1>Einstellungen</h1>

    <?php if ($message): ?><div class="flash ok"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <?php if ($error): ?><div class="flash err"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

    <form method="post">
        <input type="hidden" name="action" value="save_email">
        <section class="settings-section">
            <h2>E-Mail</h2>
            <div class="form-row">
                <label for="smtp_host">SMTP Host</label>
                <input id="smtp_host" name="smtp_host" value="<?= htmlspecialchars((string)$email['smtp_host'], ENT_QUOTES, 'UTF-8') ?>" placeholder="smtp.example.com">
            </div>
            <div class="form-row">
                <label for="smtp_port">Port</label>
                <input id="smtp_port" name="smtp_port" type="number" min="1" max="65535" value="<?= (int)$email['smtp_port'] ?>">
            </div>
            <div class="form-row">
                <label for="smtp_secure">Verschlüsselung</label>
                <select id="smtp_secure" name="smtp_secure">
                    <?php $sec=$email['smtp_secure']; ?>
                    <option value="tls" <?= $sec==='tls'?'selected':'' ?>>TLS</option>
                    <option value="ssl" <?= $sec==='ssl'?'selected':'' ?>>SSL</option>
                    <option value="none" <?= $sec==='none'?'selected':'' ?>>Keine</option>
                </select>
            </div>
            <div class="form-row">
                <label for="smtp_username">Benutzername</label>
                <input id="smtp_username" name="smtp_username" value="<?= htmlspecialchars((string)$email['smtp_username'], ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="form-row">
                <label for="smtp_password">Passwort</label>
                <input id="smtp_password" name="smtp_password" type="password" value="<?= htmlspecialchars((string)$email['smtp_password'], ENT_QUOTES, 'UTF-8') ?>" autocomplete="new-password">
            </div>
            <div class="form-row">
                <label for="from_address">Absender-Adresse</label>
                <input id="from_address" name="from_address" type="email" value="<?= htmlspecialchars((string)$email['from_address'], ENT_QUOTES, 'UTF-8') ?>" placeholder="noreply@example.com">
            </div>
            <div class="form-row">
                <label for="from_name">Absender-Name</label>
                <input id="from_name" name="from_name" value="<?= htmlspecialchars((string)$email['from_name'], ENT_QUOTES, 'UTF-8') ?>" placeholder="SimpleWebAuth">
            </div>
            <div class="note">Hinweis: PHPMailer benötigt derzeit ein Klartext-Passwort für die SMTP-Authentifizierung. Ein Passwort-Hash kann nicht verwendet werden.</div>
            <div class="form-actions">
                <button type="submit">Speichern</button>
                <a href="index.php" class="button-link" style="margin-left:8px;">Abbrechen</a>
            </div>
        </section>
    </form>

    <!-- Separate form for test email to avoid overwriting settings unintentionally -->
    <form method="post">
        <input type="hidden" name="action" value="test_email">
        <section class="settings-section">
            <h2>E-Mail – Test senden</h2>
            <div class="form-row">
                <label for="test_to">Empfänger</label>
                <input id="test_to" name="test_to" type="email" placeholder="you@example.com" required>
            </div>
            <div class="note">Verwendet die aktuell gespeicherten SMTP-Einstellungen.</div>
            <div class="form-actions">
                <button type="submit">Test-E-Mail senden</button>
            </div>
        </section>
    </form>

    <!-- Weitere Kategorien können später als weitere .settings-section ergänzt werden. -->

    <p><a href="index.php">← Zurück zum Dashboard</a></p>
</div>
</body>
</html>
