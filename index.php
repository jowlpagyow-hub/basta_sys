<?php
    session_start();
    include "config/database.php";

    // If the user is already logged in, send them to the appropriate dashboard
    if (isset($_SESSION["role"])) {
        if ($_SESSION["role"] == "admin") {
            header("Location: admin/dashboard.php");
        } else {
            header("Location: student/dashboard.php");
        }
        exit;
    }

    $error = "";

    //joel ako nagasdjabnwjhbeje

    if (isset($_POST["login"])) {
        // Get data from login form
        $username = trim($_POST["username"]);
        $password = $_POST["password"];

        if (!empty($username) && !empty($password)) {
            // Use prepared statements to prevent SQL injection
            $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE username = ? LIMIT 1");
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if (mysqli_num_rows($result) == 1) {
                $user = mysqli_fetch_assoc($result);
                
                if (password_verify($password, $user["password"])) {
                    // Prevent session fixation attacks
                    session_regenerate_id(true);

                    $_SESSION["user_id"] = $user["id"];
                    $_SESSION["full_name"] = $user["full_name"];
                    $_SESSION["role"] = $user["role"];

                    if ($user["role"] == "admin") {
                        header("Location: admin/dashboard.php");
                    } else {
                        header("Location: student/dashboard.php");
                    }
                    exit;
                }
            }
            mysqli_stmt_close($stmt);
        }

        // Generic error message to prevent username enumeration
        $error = "Invalid username or password.";
    }
?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - Student Portal</title>
    <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
<div class="container">
    <div class="login-box">
        <div class="card">
            <div class="card-body p-4">
                <h2 class="text-center">Student Portal</h2>
                <p class="text-center text-muted">Admin and Student Login</p>
                
                <?php if ($error != "") { ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                <?php } ?>

                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button class="btn btn-primary w-100" type="submit" name="login">Login</button>
                </form>
            </div>
        </div>
    </div>
</div>
</body>
</html>