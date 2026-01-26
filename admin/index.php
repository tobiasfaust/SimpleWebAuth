<?php
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
<html>
<head><meta charset="UTF-8"><title>Admin Dashboard</title>
<link rel="stylesheet" href="style.css"></head>
<body>
<div class="container">
<?php if ($loggedUser): ?><div class="welcome"><a href="?logout=1" style="text-decoration:none; margin-right:8px;" title="Logout">🚪</a>Willkommen <?= htmlspecialchars($loggedUser, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
<h1>Admin Dashboard</h1>
<nav>
<a href="users.php">Userverwaltung</a>
<a href="audit.php">Audit-Log</a>
</nav>
</div>
</body>
</html>