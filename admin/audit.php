<?php
$logDir = __DIR__ . '/../audit';
$files = glob($logDir . '/*.log');
rsort($files);
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
    <h1>Audit Log</h1>

    <?php if (empty($files)): ?>
        <p>Keine Audit-Einträge vorhanden.</p>
    <?php else: ?>
        <?php foreach ($files as $file): ?>
            <h3><?= htmlspecialchars(basename($file)) ?></h3>
            <pre class="audit">
<?= htmlspecialchars(implode("\n", array_reverse((array) file($file, FILE_IGNORE_NEW_LINES))), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
            </pre>
        <?php endforeach; ?>
    <?php endif; ?>

    <p>
        <a href="index.php">← Zurück zum Dashboard</a>
    </p>
</div>

</body>
</html>
