<?php
include 'db.php';  
$adminPasscode = "Eat097";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $passcode = $_POST['passcode'];

    if ($passcode !== $adminPasscode) {
        echo "<script>alert('Invalid passcode. Please try again.'); window.history.back();</script>";
        exit;
    }

    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    if (!$stmt) {
        echo "Error preparing statement: " . $conn->error;
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    
    $stmt->bind_param("ss", $username, $hashedPassword);

    if ($stmt->execute()) {
        echo "<script>alert('Account created successfully!'); window.location.href='index.php';</script>";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>
