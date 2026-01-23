<?php
// Userverwaltung: Quelle ist users/*.key; pro User synchrones users/<id>.json

$usersDir = __DIR__ . '/../users';
$tokensDir = __DIR__ . '/../tokens';
$auditLog = __DIR__ . '/../audit/' . date('Y-m-d') . '.log';

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

function read_json(string $file): array {
        if (!is_file($file)) return [];
        $raw = file_get_contents($file);
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
}

function write_json(string $file, array $data): bool {
        $tmp = $file . '.tmp';
        $ok = file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) !== false;
        if ($ok) {
                return rename($tmp, $file);
        }
        return false;
}

function ensure_user_json(string $usersDir, string $username): array {
        $jsonPath = $usersDir . '/' . $username . '.json';
        $keyPath  = $usersDir . '/' . $username . '.key';

        $existing = read_json($jsonPath);
        $now = time();
        if (!$existing) {
                $created = $now;
                $lastKeyGen = is_file($keyPath) ? filemtime($keyPath) ?: $now : $now;
                $data = [
                        'id' => $username,
                        'email' => '',
                        'created_at' => $created,
                        'updated_at' => $created,
                        'last_key_generated_at' => $lastKeyGen,
                'cookie_exp_seconds' => 60*60*24*30,
                'enabled' => 1,
                ];
                write_json($jsonPath, $data);
                return $data;
        }
        // Keep last_key_generated_at in sync with .key mtime
        $mtime = is_file($keyPath) ? filemtime($keyPath) ?: ($existing['last_key_generated_at'] ?? $now) : ($existing['last_key_generated_at'] ?? $now);
        if (($existing['last_key_generated_at'] ?? null) !== $mtime) {
                $existing['last_key_generated_at'] = $mtime;
                write_json($jsonPath, $existing);
        }
        return $existing;
}

function password_complexity_ok(string $password): bool {
    $groups = 0;
    if (preg_match('/[A-Z]/', $password)) $groups++;
    if (preg_match('/[a-z]/', $password)) $groups++;
    if (preg_match('/\d/', $password)) $groups++;
    if (preg_match('/[^A-Za-z0-9]/', $password)) $groups++;
    return $groups >= 3;
}

function audit(string $logFile, string $line): void {
        file_put_contents($logFile, date('c') . ' ' . $line . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
}

// Aktionen (AJAX/POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';
        header('Content-Type: application/json; charset=UTF-8');

        if ($action === 'create_user') {
                $username = trim($_POST['username'] ?? '');
                $email = trim($_POST['email'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $password2 = (string)($_POST['password2'] ?? '');
                if ($username === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
                        http_response_code(400);
                        echo json_encode(['ok' => false, 'error' => 'invalid_username']);
                        exit;
                }
                $keyPath = $usersDir . '/' . $username . '.key';
                $jsonPath = $usersDir . '/' . $username . '.json';
                if (is_file($keyPath) || is_file($jsonPath)) {
                        http_response_code(409);
                        echo json_encode(['ok' => false, 'error' => 'user_exists']);
                        exit;
                }
            if ($password === '' || $password2 === '' || $password !== $password2) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'password_mismatch']);
                exit;
            }
            if (!password_complexity_ok($password)) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'password_weak']);
                exit;
            }
            $hash = password_hash($password, PASSWORD_DEFAULT);
                file_put_contents($keyPath, $hash, LOCK_EX);
                $data = ensure_user_json($usersDir, $username);
                $data['email'] = $email;
                $data['updated_at'] = time();
                write_json($jsonPath, $data);
                audit($auditLog, 'ADMIN_USER_CREATED user=' . $username);
            echo json_encode(['ok' => true, 'user' => $username]);
                exit;
        }

        if ($action === 'update_email') {
                $username = trim($_POST['username'] ?? '');
                $email = trim($_POST['email'] ?? '');
                $jsonPath = $usersDir . '/' . $username . '.json';
                $data = ensure_user_json($usersDir, $username);
                $data['email'] = $email;
                $data['updated_at'] = time();
                write_json($jsonPath, $data);
                audit($auditLog, 'ADMIN_EMAIL_UPDATED user=' . $username);
                echo json_encode(['ok' => true]);
                exit;
        }

        if ($action === 'set_expiry') {
                $username = trim($_POST['username'] ?? '');
                $seconds = (int)($_POST['seconds'] ?? 0);
                if ($seconds < 60 || $seconds > 60*60*24*365) {
                        http_response_code(400);
                        echo json_encode(['ok' => false, 'error' => 'invalid_expiry']);
                        exit;
                }
                $jsonPath = $usersDir . '/' . $username . '.json';
                $data = ensure_user_json($usersDir, $username);
                $data['cookie_exp_seconds'] = $seconds;
                $data['updated_at'] = time();
                write_json($jsonPath, $data);
                audit($auditLog, 'ADMIN_EXPIRY_SET user=' . $username . ' seconds=' . $seconds);
            echo json_encode(['ok' => true, 'seconds' => $seconds]);
                exit;
        }

            if ($action === 'change_password') {
                $username = trim($_POST['username'] ?? '');
                $password = (string)($_POST['password'] ?? '');
                $password2 = (string)($_POST['password2'] ?? '');
                if ($username === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
                    http_response_code(400);
                    echo json_encode(['ok' => false, 'error' => 'invalid_username']);
                    exit;
                }
                if ($password === '' || $password2 === '' || $password !== $password2) {
                    http_response_code(400);
                    echo json_encode(['ok' => false, 'error' => 'password_mismatch']);
                    exit;
                }
                if (!password_complexity_ok($password)) {
                    http_response_code(400);
                    echo json_encode(['ok' => false, 'error' => 'password_weak']);
                    exit;
                }
                $keyPath = $usersDir . '/' . $username . '.key';
                if (!is_file($keyPath)) {
                    http_response_code(404);
                    echo json_encode(['ok' => false, 'error' => 'user_not_found']);
                    exit;
                }
                $hash = password_hash($password, PASSWORD_DEFAULT);
                file_put_contents($keyPath, $hash, LOCK_EX);
                $jsonPath = $usersDir . '/' . $username . '.json';
                $data = ensure_user_json($usersDir, $username);
                $data['updated_at'] = time();
                write_json($jsonPath, $data);
                audit($auditLog, 'USER_PASSWORD_CHANGED by ' . ' for user=' . $username . ' ip: ' . ($_SERVER['REMOTE_ADDR'] ?? '-'));
                echo json_encode(['ok' => true]);
                exit;
            }

        if ($action === 'toggle_enabled') {
            $username = trim($_POST['username'] ?? '');
            $enabled = isset($_POST['enabled']) ? (int)$_POST['enabled'] : null;
            if ($enabled === null || ($enabled !== 0 && $enabled !== 1)) {
                echo json_encode(['ok' => false, 'error' => 'invalid_enabled']);
                exit;
            }
            $jsonPath = $usersDir . '/' . $username . '.json';
            $data = ensure_user_json($usersDir, $username);
            $data['enabled'] = $enabled;
            $data['updated_at'] = time();
            write_json($jsonPath, $data);
            audit($auditLog, 'ADMIN_USER_ENABLED user=' . $username . ' enabled=' . $enabled);
            echo json_encode(['ok' => true, 'enabled' => $enabled]);
            exit;
        }

        if ($action === 'delete_user') {
                $username = trim($_POST['username'] ?? '');
                $keyPath = $usersDir . '/' . $username . '.key';
                $jsonPath = $usersDir . '/' . $username . '.json';
                $ok = true;
                if (is_file($keyPath)) $ok = $ok && unlink($keyPath);
                if (is_file($jsonPath)) $ok = $ok && unlink($jsonPath);
                audit($auditLog, 'ADMIN_USER_DELETED user=' . $username);
                echo json_encode(['ok' => $ok]);
                exit;
        }

        if ($action === 'generate_qr') {
                $username = trim($_POST['username'] ?? '');
                $data = ensure_user_json($usersDir, $username);
                $t = bin2hex(random_bytes(16));
                $exp = time() + 900; // Token gültig für 15 Minuten
                $tokenData = ['user' => $username, 'exp' => $exp];
                file_put_contents($tokensDir . '/' . $t . '.json', json_encode($tokenData), LOCK_EX);
                audit($auditLog, 'ADMIN_TOKEN_CREATED user=' . $username);
                $link = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https://' : 'http://')
                            . $_SERVER['HTTP_HOST'] . '/authadmin/auth.php?token=' . $t;
                echo json_encode(['ok' => true, 'link' => $link]);
                exit;
        }

        if ($action === 'get_user_info') {
            $username = trim($_POST['username'] ?? '');
            $data = ensure_user_json($usersDir, $username);
            // letzte Loginfreigabe aus Audit-Logs ermitteln
            $lastLoginAudit = null;
            $logDir = __DIR__ . '/../audit';
            $files = glob($logDir . '/*.log');
            rsort($files);
            foreach ($files as $lf) {
                $lines = @file($lf, FILE_IGNORE_NEW_LINES);
                if (!$lines) continue;
                for ($i = count($lines) - 1; $i >= 0; $i--) {
                    $line = $lines[$i];
                    if (strpos($line, ' LOGIN_GRANTED user=' . $username . ' ') !== false) {
                        $ts = substr($line, 0, 25);
                        $t = strtotime($ts);
                        if ($t) { $lastLoginAudit = $t; }
                        break 2;
                    }
                }
            }
            echo json_encode([
                'ok' => true,
                'user' => $data['id'],
                'email' => $data['email'] ?? '',
                'created_at' => $data['created_at'] ?? null,
                'updated_at' => $data['updated_at'] ?? null,
                'last_key_generated_at' => $data['last_key_generated_at'] ?? null,
                'cookie_exp_seconds' => $data['cookie_exp_seconds'] ?? null,
                'enabled' => $data['enabled'] ?? 1,
                'last_login_audit' => $lastLoginAudit
            ]);
            exit;
        }

        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'unknown_action']);
        exit;
}

// Liste aller Nutzer basierend auf *.key; stelle *.json sicher
$keyFiles = glob($usersDir . '/*.key');
sort($keyFiles);
$users = [];
foreach ($keyFiles as $keyFile) {
        $username = basename($keyFile, '.key');
        $data = ensure_user_json($usersDir, $username);
        $users[] = $data;
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
        <meta charset="UTF-8">
        <title>Userverwaltung</title>
        <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
    <?php if ($loggedUser): ?><div class="welcome">Willkommen <?= htmlspecialchars($loggedUser, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <h1>Userverwaltung</h1>
        <div class="actions-bar">
                <button id="btnCreate">+ Benutzer anlegen</button>
        </div>

        <div id="toast" class="toast" style="display:none;"></div>

        <table>
                <tr>
                        <th>Benutzername</th>
                        <th>Passwort</th>
                        <th>Email</th>
                        <th>Cookie-Ablauf (Sek.)</th>
                        <th>Aktionen</th>
                </tr>
                    <?php if (empty($users)): ?>
                        <tr><td colspan="5">Keine Benutzer vorhanden.</td></tr>
                <?php else: foreach ($users as $u): ?>
                        <tr data-user="<?= htmlspecialchars($u['id'], ENT_QUOTES, 'UTF-8') ?>" data-enabled="<?= isset($u['enabled']) ? (int)$u['enabled'] : 1 ?>">
                                <td><?= htmlspecialchars($u['id'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td>
                                <span class="pw-view" data-role="pw-view">**********</span>
                                <div class="pw-edit" data-role="pw-edit" style="display:none;">
                                    <div class="input-group">
                                        <input type="password" class="pw1" placeholder="Neues Passwort">
                                    </div>
                                    <div class="input-group">
                                        <input type="password" class="pw2" placeholder="Passwort wiederholen">
                                    </div>
                                    <div class="hint pw-hint">Mindestens 3 Gruppen: Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen.</div>
                                    <div class="modal-actions">
                                        <button type="button" class="pw-save">Speichern</button>
                                        <button type="button" class="pw-cancel secondary">Abbrechen</button>
                                    </div>
                                </div>
                            </td>
                                <td>
                                        <span class="email-view" data-role="email-view"><?= htmlspecialchars($u['email'] ?? '', ENT_QUOTES, 'UTF-8') ?></span>
                                        <input class="email-edit" data-role="email-edit" type="email" value="<?= htmlspecialchars($u['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>" style="display:none;" />
                                </td>
                                <td>
                                    <span class="expiry-view" data-role="expiry-view"><?=(int)($u['cookie_exp_seconds'] ?? (60*60*24*30))?></span>
                                    <input class="expiry-edit" data-role="expiry-edit" type="number" min="60" max="31536000" step="60" value="<?= (int)($u['cookie_exp_seconds'] ?? (60*60*24*30)) ?>" style="display:none;" />
                                </td>
                                <td>
                                        <button class="btn-qr">QR-Code</button>
                                        <button class="btn-toggle"><?= (isset($u['enabled']) ? (int)$u['enabled'] : 1) ? 'Deaktivieren' : 'Aktivieren' ?></button>
                                        <button class="btn-info">Info</button>
                                        <button class="btn-delete danger">Löschen</button>
                                </td>
                        </tr>
                <?php endforeach; endif; ?>
        </table>

        <p>
                <a href="index.php">← Zurück zum Dashboard</a>
        </p>
</div>

<!-- Create User Modal -->
<div id="modalCreate" class="modal" style="display:none;">
    <div class="modal-content">
        <h3>Benutzer anlegen</h3>
        <label>Benutzername</label>
        <input type="text" id="createUsername" placeholder="username">
        <label>Email</label>
        <input type="email" id="createEmail" placeholder="name@example.com">
        <label>Passwort</label>
        <div class="input-group">
            <input type="password" id="createPw1" placeholder="Passwort">
        </div>
        <div class="input-group">
            <input type="password" id="createPw2" placeholder="Passwort wiederholen">
        </div>
        <div class="hint">Mindestens 3 Gruppen: Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen.</div>
        <div class="modal-actions">
            <button id="createSave">Speichern</button>
            <button id="createCancel" class="secondary">Abbrechen</button>
        </div>
        <div id="createHint" class="hint"></div>
    </div>
</div>

<!-- Confirm Delete Modal -->
<div id="modalDelete" class="modal" style="display:none;">
    <div class="modal-content">
        <h3>Benutzer löschen?</h3>
        <p id="deleteUserText"></p>
        <div class="modal-actions">
            <button id="deleteConfirm" class="danger">Löschen</button>
            <button id="deleteCancel" class="secondary">Abbrechen</button>
        </div>
    </div>
    <input type="hidden" id="deleteUsername">
    </div>

<!-- Confirm Toggle Enabled Modal -->
<div id="modalToggle" class="modal" style="display:none;">
    <div class="modal-content">
        <h3>Benutzerstatus ändern</h3>
        <p id="toggleUserText"></p>
        <div class="modal-actions">
            <button id="toggleConfirm" class="danger">Bestätigen</button>
            <button id="toggleCancel" class="secondary">Abbrechen</button>
        </div>
    </div>
    <input type="hidden" id="toggleUsername">
    <input type="hidden" id="toggleEnabled">
    </div>

<!-- Info Modal -->
<div id="modalInfo" class="modal" style="display:none;">
    <div class="modal-content">
        <h3>Benutzerdaten</h3>
        <div id="infoContent"></div>
        <div class="modal-actions">
            <button id="infoClose" class="secondary">Schließen</button>
        </div>
    </div>
</div>

<script>
function showToast(msg, ok=true) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast ' + (ok ? 'success' : 'error');
    t.style.display = 'block';
    setTimeout(() => { t.style.display = 'none'; }, 3000);
}

function post(action, body) {
    const fd = new FormData();
    fd.append('action', action);
    Object.entries(body || {}).forEach(([k,v]) => fd.append(k, v));
    const target = window.location.pathname; // immer zur aktuellen Seite posten (ohne Query)
    return fetch(target, { method: 'POST', body: fd, credentials: 'same-origin' }).then(r => r.json());
}

// Email inline edit
document.querySelectorAll('tr[data-user]').forEach(row => {
    const username = row.getAttribute('data-user');
    const view = row.querySelector('[data-role="email-view"]');
    const edit = row.querySelector('[data-role="email-edit"]');
    view.addEventListener('click', () => {
        view.style.display = 'none';
        edit.style.display = 'inline-block';
        edit.focus();
    });
    const commit = () => {
        const email = edit.value;
        post('update_email', { username, email }).then(resp => {
            if (resp.ok) {
                view.textContent = email;
            }
            edit.style.display = 'none';
            view.style.display = 'inline';
        });
    };
    edit.addEventListener('blur', commit);
    edit.addEventListener('keydown', (e) => { if (e.key === 'Enter') commit(); });
});

// Ablaufzeit inline edit (wie Email)
document.querySelectorAll('tr[data-user]').forEach(row => {
    const username = row.getAttribute('data-user');
    const v = row.querySelector('[data-role="expiry-view"]');
    const e = row.querySelector('[data-role="expiry-edit"]');
    v.addEventListener('click', () => {
        v.style.display = 'none';
        e.style.display = 'inline-block';
        e.focus();
    });
    const commitExp = () => {
        const seconds = e.value;
        post('set_expiry', { username, seconds }).then(resp => {
            if (resp.ok) { v.textContent = resp.seconds; }
            e.style.display = 'none';
            v.style.display = 'inline';
        });
    };
    e.addEventListener('blur', commitExp);
    e.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') commitExp(); });
});

// Generate QR on click
document.querySelectorAll('.btn-qr').forEach(btn => {
    btn.addEventListener('click', () => {
        const row = btn.closest('tr[data-user]');
        const username = row.getAttribute('data-user');
        post('generate_qr', { username }).then(resp => {
            if (resp.ok && resp.link) {
                window.location.href = 'qrcode.php?link=' + encodeURIComponent(resp.link);
            }
        });
    });
});

// Cookie deaktivieren mit Bestätigungsdialog
document.querySelectorAll('.btn-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
        const row = btn.closest('tr[data-user]');
        const username = row.getAttribute('data-user');
        const current = parseInt(row.getAttribute('data-enabled') || '1', 10);
        const next = current ? 0 : 1;
        document.getElementById('toggleUsername').value = username;
        document.getElementById('toggleEnabled').value = String(next);
        document.getElementById('toggleUserText').textContent = (next ? 'Benutzer ' + username + ' aktivieren?' : 'Benutzer ' + username + ' deaktivieren?');
        document.getElementById('modalToggle').style.display = 'block';
    });
});
document.getElementById('toggleCancel').addEventListener('click', () => {
    document.getElementById('modalToggle').style.display = 'none';
});
document.getElementById('toggleConfirm').addEventListener('click', () => {
    const username = document.getElementById('toggleUsername').value;
    const enabled = document.getElementById('toggleEnabled').value;
    post('toggle_enabled', { username, enabled }).then(resp => {
        document.getElementById('modalToggle').style.display = 'none';
        if (resp && resp.ok) {
            const row = document.querySelector('tr[data-user="' + username + '"]');
            if (row) {
                row.setAttribute('data-enabled', String(resp.enabled));
                const btn = row.querySelector('.btn-toggle');
                if (btn) btn.textContent = resp.enabled ? 'Deaktivieren' : 'Aktivieren';
            }
            showToast(resp.enabled ? 'Benutzer aktiviert.' : 'Benutzer deaktiviert.', true);
        } else {
            showToast('Aktion fehlgeschlagen.', false);
        }
    });
});

// Info modal
document.querySelectorAll('.btn-info').forEach(btn => {
    btn.addEventListener('click', () => {
        const row = btn.closest('tr[data-user]');
        const username = row.getAttribute('data-user');
        post('get_user_info', { username }).then(data => {
            if (!data || !data.ok) return;
            const lastLoginAudit = data.last_login_audit ? new Date(data.last_login_audit*1000).toLocaleString() : '—';
            const html = `
                <table class="kv">
                    <tr><th>Benutzer</th><td>${data.user}</td></tr>
                    <tr><th>Email</th><td>${(data.email||'')}</td></tr>
                    <tr><th>Erstellt</th><td>${data.created_at? new Date(data.created_at*1000).toLocaleString(): '—'}</td></tr>
                    <tr><th>Letzte Änderung</th><td>${data.updated_at? new Date(data.updated_at*1000).toLocaleString(): '—'}</td></tr>
                    <tr><th>Letzte Key-Generierung</th><td>${data.last_key_generated_at? new Date(data.last_key_generated_at*1000).toLocaleString(): '—'}</td></tr>
                    <tr><th>Cookie-Ablauf (Sek.)</th><td>${data.cookie_exp_seconds||0}</td></tr>
                    <tr><th>Status</th><td>${(data.enabled? 'Aktiviert' : 'Deaktiviert')}</td></tr>
                    <tr><th>Letzte Loginfreigabe</th><td>${lastLoginAudit}</td></tr>
                </table>`;
            document.getElementById('infoContent').innerHTML = html;
            document.getElementById('modalInfo').style.display = 'block';
        });
    });
});
document.getElementById('infoClose').addEventListener('click', () => {
    document.getElementById('modalInfo').style.display = 'none';
});

// Delete user
document.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', () => {
        const row = btn.closest('tr[data-user]');
        const username = row.getAttribute('data-user');
        document.getElementById('deleteUsername').value = username;
        document.getElementById('deleteUserText').textContent = 'Benutzer ' + username + ' wirklich löschen?';
        document.getElementById('modalDelete').style.display = 'block';
    });
});
document.getElementById('deleteCancel').addEventListener('click', () => {
    document.getElementById('modalDelete').style.display = 'none';
});
document.getElementById('deleteConfirm').addEventListener('click', () => {
    const username = document.getElementById('deleteUsername').value;
    post('delete_user', { username }).then(resp => {
        document.getElementById('modalDelete').style.display = 'none';
        if (resp.ok) location.reload();
    });
});

// Create user
document.getElementById('btnCreate').addEventListener('click', () => {
    document.getElementById('modalCreate').style.display = 'block';
});
document.getElementById('createCancel').addEventListener('click', () => {
    document.getElementById('modalCreate').style.display = 'none';
});
document.getElementById('createSave').addEventListener('click', () => {
    const username = document.getElementById('createUsername').value.trim();
    const email = document.getElementById('createEmail').value.trim();
    const password = document.getElementById('createPw1').value;
    const password2 = document.getElementById('createPw2').value;
    if (password !== password2) {
        document.getElementById('createHint').textContent = 'Passwörter stimmen nicht überein.';
        return;
    }
    if (!pwComplex(password)) {
        document.getElementById('createHint').textContent = 'Passwort ist zu schwach (mind. 3 Gruppen).';
        return;
    }
    post('create_user', { username, email, password, password2 }).then(resp => {
        if (resp.ok) {
            document.getElementById('modalCreate').style.display = 'none';
            location.reload();
        } else {
            document.getElementById('createHint').textContent = 'Fehler: ' + (resp.error || 'unbekannt');
        }
    });
});

function pwComplex(pw) {
    let groups = 0;
    if (/[A-Z]/.test(pw)) groups++;
    if (/[a-z]/.test(pw)) groups++;
    if (/\d/.test(pw)) groups++;
    if (/[^A-Za-z0-9]/.test(pw)) groups++;
    return groups >= 3;
}

// Passwort inline ändern
document.querySelectorAll('tr[data-user]').forEach(row => {
    const username = row.getAttribute('data-user');
    const view = row.querySelector('[data-role="pw-view"]');
    const edit = row.querySelector('[data-role="pw-edit"]');
    const saveBtn = edit ? edit.querySelector('.pw-save') : null;
    const cancelBtn = edit ? edit.querySelector('.pw-cancel') : null;
    const pw1 = edit ? edit.querySelector('.pw1') : null;
    const pw2 = edit ? edit.querySelector('.pw2') : null;
    if (view && edit && saveBtn && cancelBtn && pw1 && pw2) {
        view.addEventListener('click', () => {
            view.style.display = 'none';
            edit.style.display = 'block';
            pw1.focus();
        });
        cancelBtn.addEventListener('click', () => {
            edit.style.display = 'none';
            view.style.display = 'inline';
            pw1.value = '';
            pw2.value = '';
        });
        saveBtn.addEventListener('click', () => {
            const p1 = pw1.value;
            const p2 = pw2.value;
            if (p1 !== p2) { showToast('Passwörter stimmen nicht überein.', false); return; }
            if (!pwComplex(p1)) { showToast('Passwort ist zu schwach (mind. 3 Gruppen).', false); return; }
            post('change_password', { username, password: p1, password2: p2 }).then(resp => {
                if (resp && resp.ok) {
                    showToast('Passwort geändert.', true);
                    edit.style.display = 'none';
                    view.style.display = 'inline';
                    pw1.value = '';
                    pw2.value = '';
                } else {
                    showToast('Fehler beim Ändern.', false);
                }
            });
        });
    }
});
</script>
</body>
</html>
