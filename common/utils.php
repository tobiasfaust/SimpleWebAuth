<?php
// Common utilities shared across admin and public scripts
$__ROOT = dirname(__DIR__);
const ROOT_DIR = __DIR__ . '/..';
const USERS_DIR = ROOT_DIR . '/users';
const TOKENS_DIR = ROOT_DIR . '/tokens';
const AUDIT_DIR  = ROOT_DIR . '/audit';
const SETTINGS_PATH = ROOT_DIR . '/settings.json';
const SECRET_PATH   = ROOT_DIR . '/secret.key';
// Autoload Path is configurable via settings.json (global.autoload_path)

function current_audit_log_path(): string {
    return AUDIT_DIR . '/' . date('Y-m-d') . '.log';
}

function get_secret_key(): string {
    $raw = @file_get_contents(SECRET_PATH);
    return is_string($raw) ? trim($raw) : '';
}

function read_json(string $file): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function write_json(string $file, array $data): bool {
    $tmp = $file . '.tmp';
    $payload = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($payload === false) return false;
    $ok = file_put_contents($tmp, $payload, LOCK_EX) !== false;
    if ($ok) return @rename($tmp, $file);
    return false;
}

function read_json_assoc(string $file): array { return read_json($file); }
function write_json_assoc(string $file, array $data): bool { return write_json($file, $data); }

function password_complexity_ok(string $password): bool {
    $groups = 0;
    if (preg_match('/[A-Z]/', $password)) $groups++;
    if (preg_match('/[a-z]/', $password)) $groups++;
    if (preg_match('/\d/', $password)) $groups++;
    if (preg_match('/[^A-Za-z0-9]/', $password)) $groups++;
    return $groups >= 3;
}

function audit(string $logFile, string $line): void {
    @file_put_contents($logFile, date('c') . ' ' . $line . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\n", FILE_APPEND | LOCK_EX);
}

function purge_expired_tokens(string $tokensDir): void {
    $now = time();
    foreach (glob($tokensDir . '/*.json') as $tokFile) {
        $raw = @file_get_contents($tokFile);
        $tdata = json_decode($raw, true);
        if (is_array($tdata) && isset($tdata['exp']) && (int)$tdata['exp'] < $now) {
            @unlink($tokFile);
        }
    }
}

/**
 * Extract logged user from AUTH cookie (returns username or null).
 */
function get_logged_user(): ?string {
    if (empty($_COOKIE['AUTH'])) return null;
    $decoded = base64_decode($_COOKIE['AUTH'], true);
    if ($decoded === false) return null;
    $data = json_decode($decoded, true);
    if (!is_array($data) || empty($data['user'])) return null;
    $u = (string)$data['user'];
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $u)) return null;
    return $u;
}

/**
 * Render the admin welcome header with a standardized logout icon.
 */
function render_admin_welcome(string $logoutHref = 'index.php?logout=1'): void {
    $user = get_logged_user();
    if (!$user) return;
    echo '<div class="welcome">'
    .'<a href="' . htmlspecialchars($logoutHref, ENT_QUOTES, 'UTF-8') . '" class="logout-link" title="Logout">'
    .'<i class="fa-solid fa-arrow-right-from-bracket logout-icon" aria-hidden="true"></i>'
    .'</a>'
        .'  | Willkommen ' . htmlspecialchars($user, ENT_QUOTES, 'UTF-8')
        .'</div>';
}
/**
 * Try to load Composer's autoload from common locations.
 * Returns true if an autoload file was included.
 */
function require_composer_autoload(): bool {
    // Read autoload path from settings
    $settings = read_json_assoc(SETTINGS_PATH);
    $autoloadPath = '';
    if (isset($settings['global']) && isset($settings['global']['autoload_path'])) {
        $autoloadPath = trim((string)$settings['global']['autoload_path']);
    }
    if ($autoloadPath !== '' && is_file($autoloadPath)) {
        require_once $autoloadPath;
        return true;
    }
    // Fallbacks: typical locations relative to project
    $candidates = ['/var/www/vendor/autoload.php', ROOT_DIR . '/../vendor/autoload.php', ROOT_DIR . '/vendor/autoload.php'];
    foreach ($candidates as $cand) {
        if (is_file($cand)) { require_once $cand; return true; }
    }
    return false;
}
