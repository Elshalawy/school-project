<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - School Portal</title>
    <link href="./libraries/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">School Portal</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#">Dashboard</a>
                    </li>
                </ul>
                <div class="d-flex align-items-center">
                    <span class="text-white me-3">Welcome, <?php echo htmlspecialchars($_SESSION['user_name']); ?></span>
                    <form action="user.php" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-outline-light">Logout</button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <?php if (isset($_SESSION['google_auth_message'])): ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <i class="fas fa-check-circle me-2"></i>
                        <?php echo htmlspecialchars($_SESSION['google_auth_message']); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                    <?php 
                    // Clear the message after displaying
                    unset($_SESSION['google_auth_message']);
                    unset($_SESSION['google_auth_type']);
                    ?>
                <?php endif; ?>
                
                <h2>Welcome to Your Dashboard</h2>
                <p>You have successfully logged in to the School Portal.</p>
                
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">
                                    <i class="fas fa-user me-2"></i>Profile Information
                                </h5>
                                <p class="card-text">
                                    <strong>Name:</strong> <?php echo htmlspecialchars($_SESSION['user_name']); ?><br>
                                    <strong>Email:</strong> <?php echo htmlspecialchars($_SESSION['user_email'] ?? 'Not provided'); ?><br>
                                    <strong>Role:</strong> <?php echo ucfirst(htmlspecialchars($_SESSION['user_role'])); ?><br>
                                    <strong>Login Method:</strong> <?php echo isset($_SESSION['user_email']) ? 'Google OAuth' : 'Regular'; ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">
                                    <i class="fas fa-cog me-2"></i>Account Settings
                                </h5>
                                <p class="card-text">
                                    Manage your account settings and preferences.
                                </p>
                                <a href="#" class="btn btn-primary">Account Settings</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="./libraries/js/bootstrap.bundle.min.js"></script>
</body>
</html>