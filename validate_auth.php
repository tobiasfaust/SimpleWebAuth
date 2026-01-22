#!/usr/bin/env php
<?php
// Long-running RewriteMap program to validate the AUTH cookie per request in vhost configuration.
// Input: a single line (the full Cookie header)
// Output: "OK" if valid, otherwise "BAD"

$tz = getenv('TZ') ?: 'Europe/Berlin';
@date_default_timezone_set($tz);

$logFile = __DIR__ . '/audit/' . date('Y-m-d') . '.log';
$secretFile = __DIR__ . '/secret.key';
$secret = is_file($secretFile) ? trim(file_get_contents($secretFile)) : '';

// Fallback to BAD if secret missing
if ($secret === '') {
    // Still consume lines to be a valid prg: map
    while (($line = fgets(STDIN)) !== false) {
        echo "BAD\n";
        @ob_flush();
        flush();
    }
    exit(0);
}

function deny(string $logFile, string $reason, string $ip = '-'): void {
    @file_put_contents(
        $logFile,
        date('c') . " ACCESS_DENIED {$reason} ip=" . ($ip !== '' ? $ip : '-') . "\n",
        FILE_APPEND | LOCK_EX
    );
}

function parseAuthCookie(string $cookieHeader): ?string {
    if ($cookieHeader === '-' || $cookieHeader === '') {
        return null;
    }
    // Some clients/proxies may URL-encode cookie values; also quotes may be added
    foreach (explode(';', $cookieHeader) as $part) {
        $pair = explode('=', $part, 2);
        $name = trim($pair[0] ?? '');
        $value = isset($pair[1]) ? trim($pair[1]) : '';
        if ($name !== '' && strcasecmp($name, 'AUTH') === 0) {
            if ($value === '') {
                return null;
            }
            // Strip optional surrounding quotes
            if ($value[0] === '"' && substr($value, -1) === '"') {
                $value = substr($value, 1, -1);
            }
            // Decode URL-encoded sequences (e.g., %3D)
            $value = urldecode($value);
            return $value;
        }
    }
    return null;
}

while (($line = fgets(STDIN)) !== false) {
    // Erwartetes Format: "<CookieHeader>|<REMOTE_ADDR>|<X-Forwarded-For>|<REQUEST_URI>"
    $parts = explode('|', trim($line), 4);
    $cookieHeader = trim($parts[0] ?? '');
    $remoteAddr   = trim($parts[1] ?? '');
    $xff          = trim($parts[2] ?? '');
    $requestUri   = trim($parts[3] ?? '');
    // IP bestimmen: bevorzugt X-Forwarded-For (erstes Element), sonst REMOTE_ADDR
    $ip = '-';
    if ($xff !== '') {
        $ip = trim(explode(',', $xff, 2)[0]);
    } elseif ($remoteAddr !== '') {
        $ip = $remoteAddr;
    }
    $result = 'BAD';

    $auth = parseAuthCookie($cookieHeader);
    if ($auth !== null) {
        // Strict base64 decode to avoid silent false positives
        $decoded = base64_decode($auth, true);
        if ($decoded !== false) {
            $data = json_decode($decoded, true);
        } else {
            $data = null;
        }
        if (is_array($data) && isset($data['user'], $data['exp'], $data['sig'])) {
            $user = (string)$data['user'];
            // Username-Format validieren
            if (!preg_match('/^[A-Za-z0-9._-]+$/', $user)) {
                deny($logFile, 'malformed_cookie target=' . $requestUri, $ip);
            } else if ((int)$data['exp'] < time()) {
                deny($logFile, 'expired_cookie user=' . $user . ' target=' . $requestUri, $ip);
            } else {
                $expectedSig = hash_hmac('sha256', $data['user'] . '|' . $data['exp'], $secret);
                if (!hash_equals($expectedSig, (string)$data['sig'])) {
                    deny($logFile, 'invalid_signature user=' . $user . ' target=' . $requestUri, $ip);
                } else {
                    // Zusätzlich: enabled-Status aus users/<user>.json prüfen
                    $userJsonPath = __DIR__ . '/users/' . $user . '.json';
                    $userData = [];
                    if (is_file($userJsonPath)) {
                        $raw = file_get_contents($userJsonPath);
                        $userData = json_decode($raw, true);
                    }
                    if (is_array($userData) && (!isset($userData['enabled']) || (int)$userData['enabled'] === 1)) {
                        $result = 'OK';
                    } else {
                        deny($logFile, 'user_disabled user=' . $user . ' target=' . $requestUri, $ip);
                    }
                }
            }
        } else {
            deny($logFile, 'malformed_cookie target=' . $requestUri, $ip);
        }
    }

    echo $result, "\n";
    @ob_flush();
    flush();
}
