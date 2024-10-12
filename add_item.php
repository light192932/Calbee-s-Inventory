<?php
include 'db.php';
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST['name'];
    $amount = $_POST['amount'];
    $expiry_date = $_POST['expiry_date'];
    $location = $_POST['location'];


    $sql = "INSERT INTO items (name, amount, expiry_date, location) VALUES ('$name', $amount, '$expiry_date', '$location')";
    if ($conn->query($sql) === TRUE) {
        header("Location: index.php?location=$location");
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }
    $conn->close();
}
?>
