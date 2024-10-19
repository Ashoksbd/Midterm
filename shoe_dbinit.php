<?php
// dbinit.php
$servername = "localhost";
$username = "root";  // Your DB username
$password = "";      // Your DB password
$dbname = "shoe_ecommerce";  // Your DB name
//This is for the database to connect to the server
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

