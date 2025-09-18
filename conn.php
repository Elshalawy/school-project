<?php
$host = "localhost";
$username = "root";
// $password = "0b1902dfb892a81beb334d9f55129361ef37b5ba2a752eba0a3c06713182";  // Default XAMPP password is empty
$database = "school";
$conn = mysqli_connect($host, $username,"", $database);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Set charset to ensure proper handling of special characters
mysqli_set_charset($conn, "utf8mb4");