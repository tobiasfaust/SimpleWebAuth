<?php
require_once __DIR__ . '/../common/utils.php';
$logDir = AUDIT_DIR;
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

$loggedUser = get_logged_user();
?>

<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Audit Log</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css">
</head>
<body>

<div class="container">
    <?php render_admin_welcome('index.php?logout=1'); ?>
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
