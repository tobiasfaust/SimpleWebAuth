<?php
require_once __DIR__ . '/../common/utils.php';
$l = $_GET['link'] ?? '';
$loggedUser = get_logged_user();
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>QR-Code</title>
<link rel="stylesheet" href="style.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css"></head>
<body>
<div class="container">
<?php render_admin_welcome('index.php?logout=1'); ?>
<h1>QR-Code</h1>
<img src="https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=<?=urlencode($l)?>">
<p>
  <a href="<?=htmlspecialchars($l)?>" target="_blank" rel="noopener">
    <?=htmlspecialchars($l)?>
  </a>
</p>
</div>
</body>
</html>
