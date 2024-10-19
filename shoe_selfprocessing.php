<?php
// Start the session
session_start();

// Database connection class
class Database {
    private $host = 'localhost';
    private $username = 'root';
    private $password = '';
    private $database = 'shoe_ecommerce';
    public $connection;

    public function __construct() {
        $this->connection = new mysqli($this->host, $this->username, $this->password, $this->database);
        if ($this->connection->connect_error) {
            die("Connection failed: " . $this->connection->connect_error);
        }
    }

    public function close() {
        $this->connection->close();
    }
}

// Authentication class for managing users
class Auth {
    private $conn;

    public function __construct($connection) {
        $this->conn = $connection;
    }

    // Register a new user
    public function register($username, $password) {
        // Check if the username already exists
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->close();
            return "Username already exists!";
        }

        $stmt->close();

        // Insert new user
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashedPassword);
        if ($stmt->execute()) {
            return "Registration successful!";
        } else {
            return "Registration failed!";
        }
        $stmt->close();
    }

    // Login user
    public function login($username, $password) {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            return true;
        } else {
            return false;
        }
        $stmt->close();
    }

    // Check if the user is logged in
    public function isLoggedIn() {
        return isset($_SESSION['user_id']);
    }

    // Logout the user
    public function logout() {
        session_unset();
        session_destroy();
    }
}

// Product class for managing shoe products
class ShoeProduct {
    private $conn;

    public function __construct($connection) {
        $this->conn = $connection;
    }

    public function addShoe($product_name, $price, $size) {
        $stmt = $this->conn->prepare("INSERT INTO shoes (product_name, price, size) VALUES (?, ?, ?)");
        $stmt->bind_param("sdi", $product_name, $price, $size);
        $stmt->execute();
        $stmt->close();
        return "Shoe added successfully!";
    }

    public function updateShoe($id, $product_name, $price, $size) {
        $stmt = $this->conn->prepare("UPDATE shoes SET product_name = ?, price = ?, size = ? WHERE id = ?");
        $stmt->bind_param("sdii", $product_name, $price, $size, $id);
        $stmt->execute();
        $stmt->close();
        return "Shoe updated successfully!";
    }

    public function getShoeById($id) {
        $stmt = $this->conn->prepare("SELECT * FROM shoes WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }

    public function getAllShoes() {
        $stmt = $this->conn->prepare("SELECT * FROM shoes");
        $stmt->execute();
        return $stmt->get_result();
    }

    public function deleteShoe($id) {
        $stmt = $this->conn->prepare("DELETE FROM shoes WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $stmt->close();
        return "Shoe deleted successfully!";
    }
}

// Initialize classes
$db = new Database();
$auth = new Auth($db->connection);
$shoeProduct = new ShoeProduct($db->connection);

// Handle user actions (login, register, logout)
$message = "";
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['register'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $message = $auth->register($username, $password);
    } elseif (isset($_POST['login'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        if ($auth->login($username, $password)) {
            $message = "Login successful!";
        } else {
            $message = "Invalid login credentials!";
        }
    } elseif (isset($_POST['logout'])) {
        $auth->logout();
        $message = "Logged out successfully!";
    }
}

// Handle product actions (add, edit, delete)
if ($auth->isLoggedIn()) {
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
        if ($_POST['action'] == 'add_shoe') {
            $product_name = $_POST['product_name'];
            $price = $_POST['price'];
            $size = $_POST['size'];
            $message = $shoeProduct->addShoe($product_name, $price, $size);
        } elseif ($_POST['action'] == 'delete_shoe') {
            $id = $_POST['id'];
            $message = $shoeProduct->deleteShoe($id);
        } elseif ($_POST['action'] == 'edit_shoe') {
            $id = $_POST['id'];
            $product_name = $_POST['product_name'];
            $price = $_POST['price'];
            $size = $_POST['size'];
            $message = $shoeProduct->updateShoe($id, $product_name, $price, $size);
        }
    }

    // Fetch all shoes
    $shoes = $shoeProduct->getAllShoes();
    $editShoe = null;

    // Handle edit request
    if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['edit'])) {
        $id = $_GET['edit'];
        $editShoe = $shoeProduct->getShoeById($id);
    }
}
?>


<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</body>
</html>

<?php
// Close the database connection
$db->close();
?>