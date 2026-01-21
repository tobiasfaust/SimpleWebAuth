<?php $l=$_GET['link']??''; ?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>QR-Code</title>
<link rel="stylesheet" href="style.css"></head>
<body>
<div class="container">
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
