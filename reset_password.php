<?php
require_once 'conn.php';
require_once 'csrf_token.php';

// Set secure headers
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self'");

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['token'])) {
    $token = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_STRING);
    
    // Verify session token
    if (isset($_SESSION['reset_token']) && 
        isset($_SESSION['reset_token_expiry']) && 
        isset($_SESSION['reset_user_id']) &&
        $_SESSION['reset_token'] === $token &&
        time() <= $_SESSION['reset_token_expiry']) {
        
        $csrf_token = generateToken();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Password - School Portal</title>
            <link href="./libraries/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container">
                <div class="row justify-content-center mt-5">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h3 class="card-title text-center mb-4">Reset Your Password</h3>
                                <form action="user.php" method="post" id="resetForm">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <input type="hidden" name="action" value="resetPassword">
                                    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
                                    
                                    <div class="mb-3">
                                        <label for="password" class="form-label">New Password</label>
                                        <input type="password" class="form-control" id="password" name="password" required 
                                               minlength="8" placeholder="Enter your new password">
                                    </div>
                                    
                                    <div class="mb-4">
                                        <label for="confirm_password" class="form-label">Confirm Password</label>
                                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                               required minlength="8" placeholder="Confirm your new password">
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary w-100">Reset Password</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <script src="./libraries/js/bootstrap.bundle.min.js"></script>
            <script>
                document.querySelector('form').addEventListener('submit', function(e) {
                    const password = document.getElementById('password').value;
                    const confirmPassword = document.getElementById('confirm_password').value;
                    
                    if (password !== confirmPassword) {
                        e.preventDefault();
                        alert('Passwords do not match!');
                    }
                });
            </script>
        </body>
        </html>
        <?php
    } else {
        echo "Invalid or expired reset token. Please request a new password reset.";
    }
} else {
    header('Location: index.php');
    exit;
}
?>
