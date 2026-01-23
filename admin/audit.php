<?php
$logDir = __DIR__ . '/../audit';
$files = glob($logDir . '/*.log');
rsort($files);

// Liste verfügbarer Tage (yyyy-mm-dd)
$days = [];
foreach ($files as $f) {
    $b = basename($f, '.log');
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $b)) {
        $days[] = $b;
    }
}

// Standard: jüngstes Datum
$selectedDay = $days[0] ?? null;
if (!empty($_GET['day']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['day'])) {
    if (is_file($logDir . '/' . $_GET['day'] . '.log')) {
        $selectedDay = $_GET['day'];
    }
}

$selectedContent = '';
if ($selectedDay) {
    $selFile = $logDir . '/' . $selectedDay . '.log';
    $lines = @file($selFile, FILE_IGNORE_NEW_LINES);
    if (is_array($lines)) {
        // Neueste Einträge zuerst
        $selectedContent = implode("\n", array_reverse($lines));
    }
}

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
?>

<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Audit Log</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="container">
    <?php if ($loggedUser): ?><div class="welcome">Willkommen <?= htmlspecialchars($loggedUser, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <h1>Audit Log</h1>

    <?php if (empty($days)): ?>
        <p>Keine Audit-Einträge vorhanden.</p>
    <?php else: ?>
        <div class="audit-layout">
            <aside class="audit-sidebar">
                <h4>Tage</h4>
                <ul>
                    <?php foreach ($days as $day): ?>
                        <li>
                            <a href="audit.php?day=<?= htmlspecialchars($day, ENT_QUOTES, 'UTF-8') ?>"<?= $day === $selectedDay ? ' class="active"' : '' ?>>
                                <?= htmlspecialchars($day, ENT_QUOTES, 'UTF-8') ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </aside>
            <div class="audit-content">
                <h3><?= htmlspecialchars($selectedDay, ENT_QUOTES, 'UTF-8') ?></h3>
                <pre class="audit"><?= htmlspecialchars($selectedContent, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
            </div>
        </div>
    <?php endif; ?>

    <p>
        <a href="index.php">← Zurück zum Dashboard</a>
    </p>
</div>

</body>
</html>
