#!/usr/bin/env php
<?php
// Long-running RewriteMap program to validate the AUTH cookie per request in vhost configuration.
// Input: a single line (the full Cookie header)
// Output: "OK" if valid, otherwise "BAD"

$secretFile = __DIR__ . '/../secret.key';
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
    $cookieHeader = trim($line);
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
            if ((int)$data['exp'] >= time()) {
                $expectedSig = hash_hmac('sha256', $data['user'] . '|' . $data['exp'], $secret);
                if (hash_equals($expectedSig, (string)$data['sig'])) {
                    $result = 'OK';
                }
            }
        }
    }

    echo $result, "\n";
    @ob_flush();
    flush();
}
