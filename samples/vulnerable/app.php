<?php
// Training fixture only
$password = "DEMO_ONLY_REPLACE_ME_12345";
echo "<h1>" . $_GET["name"] . "</h1>";
$sql = "SELECT * FROM users WHERE name='" . $_GET["name"];
$fh = fopen("/srv/files/" . $_GET["file"], "r");
?>
