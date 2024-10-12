<?php
include 'db.php';

if (isset($_GET['id']) && isset($_GET['location'])) {
    $id = $_GET['id'];
    
    // Update the item amount in the database
    $useSql = "UPDATE items SET amount = amount - 1 WHERE id = $id AND amount > 0";
    $conn->query($useSql);

    // Get the updated amount to return it in the response
    $getAmountSql = "SELECT amount FROM items WHERE id = $id";
    $result = $conn->query($getAmountSql);
    $newAmount = $result->fetch_assoc()['amount'];

    // Prepare the response
    $response = [
        'success' => true,
        'newAmount' => $newAmount
    ];

    echo json_encode($response);
}
$conn->close();
?>



