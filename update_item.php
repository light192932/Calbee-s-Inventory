<?php
include 'db.php';
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $id = $_POST['id'];
    $name = $_POST['name'];
    $amount = $_POST['amount'];
    $expiry_date = $_POST['expiry_date'];

    $sql = "UPDATE items SET name='$name', amount=$amount, expiry_date='$expiry_date' WHERE id=$id";
    if ($conn->query($sql) === TRUE) {
        header("Location: index.php?location=" . $_POST['location']);
    } else {
        echo "Error updating record: " . $conn->error;
    }
} else {
    $id = $_GET['id'];
    $sql = "SELECT * FROM items WHERE id=$id";
    $result = $conn->query($sql);
    $item = $result->fetch_assoc();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Item</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: #fff;
            padding: 20px 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        h2 {
            margin-bottom: 20px;
            font-size: 24px;
            text-align: center;
            color: #333;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            font-size: 16px;
            border: 1px solid #ddd;
            border-radius: 5px;
            outline: none;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus {
            border-color: #5a67d8;
        }
        .button-group {
            display: flex;
            justify-content: space-between;
        }
        .button-group button {
            width: 48%;
            padding: 12px;
            font-size: 16px;
            font-weight: 500;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .button-group button.update {
            background-color: #5a67d8;
            color: white;
        }
        .button-group button.update:hover {
            background-color: #4c51bf;
        }
        .button-group button.cancel {
            background-color: #e53e3e;
            color: white;
        }
        .button-group button.cancel:hover {
            background-color: #c53030;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Update Item</h2>
        <form action="update_item.php" method="post">
            <input type="hidden" name="id" value="<?php echo $item['id']; ?>">
            <div class="form-group">
                <label for="name">Item Name</label>
                <input type="text" id="name" name="name" value="<?php echo $item['name']; ?>" required>
            </div>
            <div class="form-group">
                <label for="amount">Amount</label>
                <input type="number" id="amount" name="amount" value="<?php echo $item['amount']; ?>" required>
            </div>
            <div class="form-group">
                <label for="expiry_date">Expiry Date</label>
                <input type="date" id="expiry_date" name="expiry_date" value="<?php echo $item['expiry_date']; ?>" required>
            </div>
            <div class="button-group">
                <button type="submit" class="update">Update</button>
                <button type="button" class="cancel" onclick="window.location.href='index.php';">Cancel</button>
            </div>
        </form>
    </div>
</body>
</html>
<?php
}
$conn->close();
?>
    