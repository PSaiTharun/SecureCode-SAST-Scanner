<?php
$stmt=$db->prepare("SELECT * FROM users WHERE name=?");$stmt->bind_param("s",$_GET["name"]);$stmt->execute();
$name=htmlspecialchars($_GET["name"],ENT_QUOTES,"UTF-8");
?>
