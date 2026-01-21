<?php
$users = glob(__DIR__.'/../users/*.json');
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Userverwaltung</title>
<link rel="stylesheet" href="style.css"></head>
<body>
<div class="container">
<h1>Userverwaltung</h1>
<table>
<tr><th>ID</th><th>Email</th><th>Magic-Link</th></tr>
<?php foreach($users as $u):
$d=json_decode(file_get_contents($u),true);
$t=bin2hex(random_bytes(16));
file_put_contents(__DIR__.'/../tokens/'.$t.'.json',json_encode(['user'=>$d['id'],'exp'=>time()+900]));
$link="https://".$_SERVER['HTTP_HOST']."/authadmin/auth.php?token=$t";

file_put_contents(
    __DIR__ . '/../audit/' . date('Y-m-d') . '.log',
    date('c') . " ADMIN_TOKEN_CREATED user=" . $d['id'] . " ip=" . $_SERVER['REMOTE_ADDR'] . "\n",
    FILE_APPEND | LOCK_EX
);

?>
<tr>
<td><?=htmlspecialchars($d['id'])?></td>
<td><?=htmlspecialchars($d['email'])?></td>
<td><a href="qrcode.php?link=<?=urlencode($link)?>">QR-Code</a></td>
</tr>
<?php endforeach; ?>
</table>
</div>
</body>
</html>
