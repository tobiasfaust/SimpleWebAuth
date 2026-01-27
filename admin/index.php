<?php
require_once __DIR__ . '/../common/utils.php';
// Logout-Handler
if (isset($_GET['logout'])) {
	setcookie('AUTH', '', [
		'expires' => time() - 3600,
		'path' => '/',
		'secure' => true,
		'httponly' => true,
		'samesite' => 'Strict'
	]);
	header('Location: /authadmin');
	exit;
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Admin Dashboard</title>
<link rel="stylesheet" href="style.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css"></head>
<body>
<div class="container">
<?php render_admin_welcome('index.php?logout=1'); ?>
<h1>Admin Dashboard</h1>
<nav>
<a href="users.php">Userverwaltung</a>
<a href="audit.php">Audit-Log</a>
<a href="settings.php">Einstellungen</a>
</nav>
</div>
</body>
</html>