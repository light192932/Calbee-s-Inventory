<?php
include 'db.php';

// Handle "Use" action
if (isset($_GET['use'])) {
    $id = $_GET['use'];
    $useSql = "UPDATE items SET amount = amount - 1 WHERE id = $id AND amount > 0";
    $conn->query($useSql);

    header("Location: index.php?view=inventory&location=" . $_GET['location']);
    exit();
}

// Handle "Delete" action
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $deleteSql = "DELETE FROM items WHERE id = $id";
    $conn->query($deleteSql);

    header("Location: index.php?view=inventory&location=" . $_GET['location']);
    exit();
}

// Handle the view type (dashboard or inventory)
$view = isset($_GET['view']) ? $_GET['view'] : 'dashboard';

// Get location if in inventory mode
$location = isset($_GET['location']) ? $_GET['location'] : 'Freezer';

// Dashboard statistics queries
$totalItemsSql = "SELECT COUNT(*) AS total_items FROM items";
$totalItemsResult = $conn->query($totalItemsSql);
$totalItems = $totalItemsResult->fetch_assoc()['total_items'];

$expiringSoonSql = "SELECT COUNT(*) AS expiring_soon FROM items WHERE expiry_date <= CURDATE() + INTERVAL 7 DAY";
$expiringSoonResult = $conn->query($expiringSoonSql);
$expiringSoon = $expiringSoonResult->fetch_assoc()['expiring_soon'];

$freezerItemsSql = "SELECT COUNT(*) AS freezer_items FROM items WHERE location = 'Freezer'";
$freezerItemsResult = $conn->query($freezerItemsSql);
$freezerItems = $freezerItemsResult->fetch_assoc()['freezer_items'];

$chillerItemsSql = "SELECT COUNT(*) AS chiller_items FROM items WHERE location = 'Chiller'";
$chillerItemsResult = $conn->query($chillerItemsSql);
$chillerItems = $chillerItemsResult->fetch_assoc()['chiller_items'];

$stockroomItemsSql = "SELECT COUNT(*) AS stockroom_items FROM items WHERE location = 'Stockroom'";
$stockroomItemsResult = $conn->query($stockroomItemsSql);
$stockroomItems = $stockroomItemsResult->fetch_assoc()['stockroom_items'];

// If viewing inventory, query items based on location
if ($view === 'inventory') {
    $sql = "SELECT * FROM items WHERE location = '$location'";
    $result = $conn->query($sql);
}

// Low stock threshold
$lowStockThreshold = 5;

$lowFreezerItemsSql = "SELECT COUNT(*) AS low_freezer_items FROM items WHERE location = 'Freezer' AND amount < $lowStockThreshold";
$lowFreezerItemsResult = $conn->query($lowFreezerItemsSql);
$lowFreezerItems = $lowFreezerItemsResult->fetch_assoc()['low_freezer_items'];

$lowChillerItemsSql = "SELECT COUNT(*) AS low_chiller_items FROM items WHERE location = 'Chiller' AND amount < $lowStockThreshold";
$lowChillerItemsResult = $conn->query($lowChillerItemsSql);
$lowChillerItems = $lowChillerItemsResult->fetch_assoc()['low_chiller_items'];

$lowStockroomItemsSql = "SELECT COUNT(*) AS low_stockroom_items FROM items WHERE location = 'Stockroom' AND amount < $lowStockThreshold";
$lowStockroomItemsResult = $conn->query($lowStockroomItemsSql);
$lowStockroomItems = $lowStockroomItemsResult->fetch_assoc()['low_stockroom_items'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inventory Management Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
      <div class="sidebar">
    <h2>INVENTORY</h2>
    <div class="sidebar-links">
        <ul>
            <li><a href="?view=dashboard">Dashboard</a></li>
            <li><a href="?view=inventory&location=Freezer">Freezer</a></li>
            <li><a href="?view=inventory&location=Chiller">Chiller</a></li>
            <li><a href="?view=inventory&location=Stockroom">Stockroom</a></li>
            <li><a href="?view=add_account">Add Account</a></li>
        </ul>
    </div>
    <a href="logout.php" class="logout-link">Logout</a>
      </div>

      <div class="main-content">
    <?php if ($view === 'dashboard'): ?>
        <!-- Dashboard View -->
        <h2>Calbee's Inventory Dashboard</h2>
        <div class="dashboard-container">
        <div class="dashboard-item">
        <h4>Total Items</h4>
        <p><?php echo $totalItems; ?></p>
    </div>
        <div class="dashboard-item">
        <h4>Expiring Soon</h4>
        <p><?php echo $expiringSoon; ?></p>
    </div>
        <div class="dashboard-item">
        <h4>Freezer Items</h4>
        <p><?php echo $freezerItems; ?></p>
        <p style="color: red;">Low Stock: <?php echo $lowFreezerItems; ?></p>
    </div>
        <div class="dashboard-item">
        <h4>Chiller Items</h4>
        <p><?php echo $chillerItems; ?></p>
        <p style="color: red;">Low Stock: <?php echo $lowChillerItems; ?></p>
    </div>
        <div class="dashboard-item">
        <h4>Stockroom Items</h4>
        <p><?php echo $stockroomItems; ?></p>
        <p style="color: red;">Low Stock: <?php echo $lowStockroomItems; ?></p>
    </div>
</div>

        <!-- Add Acount -->
    <?php elseif ($view === 'add_account'): ?>
        <div class="add-account-container">
    <h2>Create Your Account</h2>
    <p>Calbee's Inventory Creating Account! Fill in the details below to create your account.</p>
    <form action="add_account.php" method="post" class="add-account-form">
    <div class="form-group">
        <input type="text" id="username" name="username" placeholder="Username" required>
    </div>
    <div class="form-group">
        <input type="password" id="password" name="password" placeholder="Password" required>
    </div>
    <div class="form-group">
        <input type="password" id="passcode" name="passcode" placeholder="Passcode" required>
    </div>
    <button type="submit" class="submit-btn">Create Account</button>
</form>
</div>
    <?php else: ?>

        <!-- Inventory View -->
        <div class="inventory-header">
            <h2><?php echo ucfirst($location); ?> Inventory</h2>
            <!-- Search Form -->
            <form method="GET" action="index.php" class="search-form">
                <input type="hidden" name="view" value="inventory">
                <input type="hidden" name="location" value="<?php echo $location; ?>">
                <input type="text" name="search" placeholder="Search items..." value="<?php echo isset($_GET['search']) ? $_GET['search'] : ''; ?>">
                <button type="submit">Search</button>
            </form>
        </div>

        <?php 
        if ($view === 'inventory') {
            $search = isset($_GET['search']) ? $_GET['search'] : '';
            $sql = "SELECT * FROM items WHERE location = '$location'";
            if (!empty($search)) {
                $sql .= " AND name LIKE '%" . $conn->real_escape_string($search) . "%'";
            }
            $result = $conn->query($sql);
        }
        ?>
        <div class="scrollable-table">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>   
                        <th>Amount</th>
                        <th>Expiry Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    if ($result->num_rows > 0) {
                        while($row = $result->fetch_assoc()) {
                            echo "<tr data-id='{$row['id']}'>
                            <td>{$row['name']}</td>
                            <td class='amount-cell'>{$row['amount']}</td>
                            <td>{$row['expiry_date']}</td>
                            <td>
                            <a href='update_item.php?id={$row['id']}'>Update</a> |
                            <a href='javascript:void(0);' onclick='useItem({$row['id']}, \"$location\");' class='use-item-link'>Use</a> |
                            <a href='index.php?view=inventory&location=$location&delete={$row['id']}' onclick='return confirm(\"Are you sure you want to delete this item?\");' class='delete-item-link'>Delete</a>
                        </td>
                    </tr>";
                        }
                    } else {
                        echo "<tr><td colspan='4'>No items found</td></tr>";
                    }
                    ?>
                </tbody>
            </table>
        </div>
        <!-- Add New Item Form -->
        <h3>Add New Item</h3>
        <form action="add_item.php" method="post">
            <input type="text" name="name" placeholder="Item Name" required>
            <input type="number" name="amount" placeholder="Amount" required>
            <input type="date" name="expiry_date" required>
            <select name="location">
                <option value="Freezer">Freezer</option>
                <option value="Chiller">Chiller</option>
                <option value="Stockroom">Stockroom</option>
            </select>
            <button type="submit">Add Item</button>
        </form>
    <?php endif; ?>
</div>

    </div>
</body>
<script>
function useItem(id, location) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "use_item.php?id=" + id + "&location=" + location, true);
    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4 && xhr.status == 200) {
            var response = JSON.parse(xhr.responseText);
            if (response.success) {
                // Update the item's amount in the table
                var amountCell = document.querySelector("tr[data-id='" + id + "'] .amount-cell");
                amountCell.innerText = response.newAmount;
            } else {
                alert("Failed to use item. Please try again.");
            }
        }
    };
    xhr.send();
}
</script>
</html>
<?php
$conn->close();
?>
