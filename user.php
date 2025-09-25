<?php
session_start();
require_once 'conn.php';
require_once "config.php";
require_once 'vendor/autoload.php'; // For Google OAuth

// Import required Google and Guzzle classes
use Google\Client;
use Google\Service\Oauth2;
use GuzzleHttp\Client as GuzzleClient;

// Set secure headers
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self'");

// Initialize CSRF protection
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
        exit;
    }
}

// config is already loaded above

// Initialize Google Client with error handling
try {
    // Initialize Google Client with configuration array
    $client = new Client([
        'application_name' => 'School Web Portal',
        'client_id' => GOOGLE_CLIENT_ID,
        'client_secret' => GOOGLE_CLIENT_SECRET,
        'redirect_uri' => GOOGLE_REDIRECT_URI,
        'access_type' => 'online',
        'prompt' => 'select_account',
        'include_granted_scopes' => true
    ]);

    // Add required scopes  
    $client->addScope(['email', 'profile']);

    // Configure Guzzle client with proper SSL settings
    $guzzleClient = new GuzzleClient([
        'verify' => false, // Only for development! Remove in production
        'timeout' => 30,
        'connect_timeout' => 30
    ]);
    $client->setHttpClient($guzzleClient);
    
    // Verify required constants are set
    if (!defined('GOOGLE_CLIENT_ID') || !defined('GOOGLE_CLIENT_SECRET')) {
        throw new Exception('Google OAuth configuration is incomplete. Please check config.php');
    }
} catch (Exception $e) {
    error_log('Google Client initialization error: ' . $e->getMessage());
    die('Error initializing Google authentication. Please check the server logs.');
}

class UserAuth {
    private $conn;
    private $googleClient;

    public function __construct($connection, $googleClient) {
        $this->conn = $connection;
        $this->googleClient = $googleClient;
    }
    /**
     * Regular login with phone and password
    */
    private function validateInput($input, $type) {
        switch($type) {
            case 'phone':
                // Remove any spaces, dashes or parentheses first
                $cleaned = preg_replace('/[\s\-\(\)]/', '', $input);
                // Check if it's exactly 11 digits, optionally starting with +
                return preg_match('/^\+?[0-9]{11}$/', $cleaned) ? $cleaned : false;
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL);
            case 'name':
                return preg_match('/^[a-zA-Z0-9\s]{2,50}$/', $input) ? $input : false;
            default:
                return false;
        }
    }

    public function login($email, $password) {
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ["success" => false, "message" => "Invalid email format"];
        }
        
        // Use proper SQL with placeholders for email only
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
    
        if($row = mysqli_fetch_assoc($result)) {
            if (password_verify($password, $row['password'])) {
                // Set session variables
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['user_name'] = $row['name'];
                $_SESSION['user_role'] = $row['role'];
                // Regenerate session ID for security
                session_regenerate_id(true);
                // Generate new CSRF token after login
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                
                return [
                    "success" => true, 
                    "message" => "Login successful. Welcome, " . htmlspecialchars($row['name']) . "!",
                    "redirect" => "dashboard.php"
                ];
            }
            return ["success" => false, "message" => "Invalid password"];
        }
        
        return ["success" => false, "message" => "Invalid email/phone or password"];
    }

    /**
     * Initiate password reset: generate token, store in session, and email link
     */
    public function initiatePasswordReset($email) {
        if (!$this->validateInput($email, 'email')) {
            return ["success" => false, "message" => "Invalid email format"];
        }

        // Look up user
        $sql = "SELECT id, name, email FROM users WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if ($user = mysqli_fetch_assoc($result)) {
            $resetToken = bin2hex(random_bytes(32));
            $expiry = time() + 3600; // 1 hour from now

            // Store token and expiry in session
            $_SESSION['reset_token'] = $resetToken;
            $_SESSION['reset_token_expiry'] = $expiry;
            $_SESSION['reset_user_id'] = $user['id'];
            $_SESSION['reset_user_email'] = $user['email'];

            // Send email
            require_once 'email_service.php';
            $emailService = new EmailService();
            if ($emailService->sendPasswordResetEmail($user['email'], $user['name'], $resetToken)) {
                return ["success" => true, "message" => "If this email is registered, you will receive reset instructions."];
            }
            return ["success" => false, "message" => "Could not send reset email. Please try again later."];
        }

        // Do not reveal whether the email exists
        return ["success" => true, "message" => "If this email is registered, you will receive reset instructions."];
    }

    public function register($name, $phone, $password, $email, $role) {
        // Validate all inputs
        if (!$this->validateInput($name, 'name')) {
            return ["success" => false, "message" => "Invalid name format"];
        }
        if (!$this->validateInput($phone, 'phone')) {
            return ["success" => false, "message" => "Invalid phone number format"];
        }
        if (!$this->validateInput($email, 'email')) {
            return ["success" => false, "message" => "Invalid email format"];
        }
        if (strlen($password) < 8) {
            return ["success" => false, "message" => "Password must be at least 8 characters long"];
        }
        if (!in_array($role, ['student', 'teacher', 'parent'])) {
            return ["success" => false, "message" => "Invalid role selected"];
        }

        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Check if phone or email already exists
        $checkSql = "SELECT * FROM users WHERE phone = ? OR email = ?";
        $stmt = mysqli_prepare($this->conn, $checkSql);
        mysqli_stmt_bind_param($stmt, "ss", $phone, $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if(mysqli_num_rows($result) > 0) {
            $row = mysqli_fetch_assoc($result);
            if ($row['phone'] === $phone) {
                return ["success" => false, "message" => "Phone number already registered"];
            }
            return ["success" => false, "message" => "Email already registered"];
        }

        // Insert new user with hashed password
        $insertSql = "INSERT INTO users (name, phone, password, email, role) VALUES (?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($this->conn, $insertSql);
        mysqli_stmt_bind_param($stmt, "sssss", $name, $phone, $hashedPassword, $email, $role);
        
        if(mysqli_stmt_execute($stmt)) {
            $new_user_id = mysqli_insert_id($this->conn);
            
            // Set session variables for new user
            $_SESSION['user_id'] = $new_user_id;
            $_SESSION['user_name'] = $name;
            $_SESSION['user_role'] = $role;
            $_SESSION['user_email'] = $email;
            
            // Regenerate session ID for security
            session_regenerate_id(true);

            return ["success" => true, "message" => "Registration successful. You can now log in.", "redirect" => "dashboard.php"];
        }
        
        return ["success" => false, "message" => "Error: " . mysqli_error($this->conn)];
    }

    /**
     * Complete password reset: validate session token and update password
     */
    public function completePasswordReset($token, $newPassword) {
        $token = trim((string)$token);
        if (strlen((string)$newPassword) < 8) {
            return ["success" => false, "message" => "Password must be at least 8 characters long"];
        }

        // Validate session token
        if (!isset($_SESSION['reset_token']) || 
            !isset($_SESSION['reset_token_expiry']) || 
            !isset($_SESSION['reset_user_id']) ||
            $_SESSION['reset_token'] !== $token ||
            time() > $_SESSION['reset_token_expiry']) {
            return ["success" => false, "message" => "Invalid or expired reset token."];
        }

        // Update password
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $updateSql = "UPDATE users SET password = ? WHERE id = ?";
        $updateStmt = mysqli_prepare($this->conn, $updateSql);
        mysqli_stmt_bind_param($updateStmt, "si", $hashedPassword, $_SESSION['reset_user_id']);
        
        if (mysqli_stmt_execute($updateStmt)) {
            // Clear reset session data
            unset($_SESSION['reset_token']);
            unset($_SESSION['reset_token_expiry']);
            unset($_SESSION['reset_user_id']);
            unset($_SESSION['reset_user_email']);
            
            return ["success" => true, "message" => "Your password has been successfully reset."];
        }
        
        return ["success" => false, "message" => "Could not update password. Please try again."];
    }

    /**
     * Get Google login URL
     */
    public function getGoogleLoginUrl() {
        try {
            // Verify Google client is properly configured
            if (!$this->googleClient) {
                throw new Exception('Google client is not properly initialized');
            }
            
            // Verify required constants are defined
            if (!defined('GOOGLE_CLIENT_ID') || empty(GOOGLE_CLIENT_ID)) {
                throw new Exception('GOOGLE_CLIENT_ID is not defined or empty');
            }
            
            if (!defined('GOOGLE_CLIENT_SECRET') || empty(GOOGLE_CLIENT_SECRET)) {
                throw new Exception('GOOGLE_CLIENT_SECRET is not defined or empty');
            }
            
            if (!defined('GOOGLE_REDIRECT_URI') || empty(GOOGLE_REDIRECT_URI)) {
                throw new Exception('GOOGLE_REDIRECT_URI is not defined or empty');
            }
            
            // Generate state parameter for CSRF protection
            $state = bin2hex(random_bytes(16));
            $_SESSION['google_auth_state'] = $state;
            
            // Configure the Google client
            $this->googleClient->setState($state);
            $this->googleClient->setAccessType('offline');
            $this->googleClient->setPrompt('consent');
            $this->googleClient->setIncludeGrantedScopes(true);
            
            // Add required scopes
            $this->googleClient->addScope([
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ]);
            
            // Log the configuration for debugging
            error_log('Google OAuth Configuration:');
            error_log('- Client ID: ' . GOOGLE_CLIENT_ID);
            error_log('- Redirect URI: ' . GOOGLE_REDIRECT_URI);
            error_log('- State: ' . $state);
            
            // Generate the auth URL
            $authUrl = $this->googleClient->createAuthUrl();
            
            if (empty($authUrl)) {
                throw new Exception('Failed to generate Google OAuth URL');
            }
            
            error_log('Google OAuth URL Generated: ' . $authUrl);
            return $authUrl;
            
        } catch (Exception $e) {
            $errorMsg = 'Error generating Google OAuth URL: ' . $e->getMessage() . 
                       ' in ' . $e->getFile() . ' on line ' . $e->getLine();
            error_log($errorMsg);
            throw new Exception('Could not generate Google login URL. ' . $e->getMessage());
        }
    }

    /**
     * Handle Google login callback
     */
    public function handleGoogleCallback($code) {
        try {
            if (empty($code)) {
                throw new Exception('Authorization code is missing');
            }
            
            // Log the callback for debugging
            error_log('Google OAuth callback received. Code: ' . substr($code, 0, 10) . '...');
            
            // Only revoke token if one exists
            if ($this->googleClient->getAccessToken()) {
                $this->googleClient->revokeToken();
            }
            
            // Verify state to prevent CSRF
            if (isset($_GET['state'])) {
                if (!isset($_SESSION['google_auth_state']) || $_GET['state'] !== $_SESSION['google_auth_state']) {
                    throw new Exception('Invalid state parameter - possible CSRF attack');
                }
                // Clear the state after verification
                unset($_SESSION['google_auth_state']);
            } else {
                throw new Exception('Missing state parameter');
            }

            // Configure CURL options for Guzzle
            $guzzleClient = new \GuzzleHttp\Client([
                'verify' => false, // Only for development! Remove in production
                'timeout' => 30,
                'connect_timeout' => 30,
                'curl' => [
                    CURLOPT_SSL_VERIFYPEER => false, // Only for development! Remove in production
                    CURLOPT_SSL_VERIFYHOST => false  // Only for development! Remove in production
                ]
            ]);
            $this->googleClient->setHttpClient($guzzleClient);

            // Clean the authorization code
            $code = trim($code);
            
            try {
                // Fetch the access token
                $token = $this->googleClient->fetchAccessTokenWithAuthCode($code);
                
                if (!is_array($token) || isset($token['error'])) {
                    $error = isset($token['error_description']) ? $token['error_description'] : 
                            (isset($token['error']) ? $token['error'] : 'Unknown error');
                    throw new Exception('Token Error: ' . $error);
                }
            } catch (\Google\Exception $e) {
                throw new Exception('Google API Error: ' . $e->getMessage());
            }

            $this->googleClient->setAccessToken($token);
            
            // Get user information from Google
            $oauth2Service = new Oauth2($this->googleClient);
            $google_account_info = $oauth2Service->userinfo->get();
            // Extract user data - only essential fields
            $email = $google_account_info->email;
            $name = $google_account_info->name;
            $google_id = $google_account_info->id;
            // Verify email is present
            if (!$email) {
                throw new Exception('Email is required for registration');
            }
            
            // Check if user exists (by email or google_id)
            $sql = "SELECT * FROM users WHERE email = ? OR google_id = ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $email, $google_id);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($row = mysqli_fetch_assoc($result)) {
                // User exists - handle login
                $isNewGoogleConnection = empty($row['google_id']);
                
                // Update existing user's Google ID if not set
                if ($isNewGoogleConnection) {
                    $updateSql = "UPDATE users SET google_id = ? WHERE id = ?";
                    $updateStmt = mysqli_prepare($this->conn, $updateSql);
                    mysqli_stmt_bind_param($updateStmt, "si", $google_id, $row['id']);
                    mysqli_stmt_execute($updateStmt);
                }
                
                // Set session variables
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['user_name'] = $row['name'];
                $_SESSION['user_role'] = $row['role'];
                $_SESSION['user_email'] = $row['email'];
                
                // Regenerate session ID for security
                session_regenerate_id(true);
                
                $message = $isNewGoogleConnection ? 
                    "Google account linked successfully! Welcome back, " . htmlspecialchars($row['name']) . "!" :
                    "Welcome back, " . htmlspecialchars($row['name']) . "!";
                
                return [
                    "success" => true, 
                    "message" => $message,
                    "redirect" => "dashboard.php",
                    "is_login" => true
                ];
            } else {
                // User doesn't exist - handle registration
                $default_role = DEFAULT_SOCIAL_LOGIN_ROLE ?? 'student';
                
                // Insert new user with Google data - only essential fields
                $insertSql = "INSERT INTO users (name, email, google_id, role) 
                             VALUES (?, ?, ?, ?)";
                $stmt = mysqli_prepare($this->conn, $insertSql);
                mysqli_stmt_bind_param($stmt, "ssss", $name, $email, $google_id, $default_role);
                
                if (mysqli_stmt_execute($stmt)) {
                    $new_user_id = mysqli_insert_id($this->conn);
                    
                    // Set session variables for new user
                    $_SESSION['user_id'] = $new_user_id;
                    $_SESSION['user_name'] = $name;
                    $_SESSION['user_role'] = $default_role;
                    $_SESSION['user_email'] = $email;
                    
                    // Regenerate session ID for security
                    session_regenerate_id(true);
                    
                    return [
                        "success" => true,
                        "message" => "Account created successfully with Google! Welcome, " . htmlspecialchars($name) . "!",
                        "redirect" => "dashboard.php",
                        "is_registration" => true
                    ];
                } else {
                    throw new Exception("Failed to create new user account: " . mysqli_error($this->conn));
                }
            }
        } catch(Exception $e) {
            return ["success" => false, "message" => "Error with Google login: " . $e->getMessage()];
        }
    }

    /**
     * Logout user
     */
    public function logout() {
        session_destroy();
        return ["success" => true, "message" => "Logged out successfully"];
    }
}

// Initialize UserAuth class
$userAuth = new UserAuth($conn, $client);

// Handle POST requests
if(isset($_SERVER["REQUEST_METHOD"]) && $_SERVER["REQUEST_METHOD"] === "POST") {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
        exit;
    }

    $response = [];
    $action = filter_input(INPUT_POST, 'action', FILTER_DEFAULT);
    
    // Validate action parameter
    if (!$action || !is_string($action)) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Invalid or missing action parameter']);
        exit;
    }
    
    // Sanitize action
    $action = trim(strip_tags($action));
    
    switch($action) {
        case 'login':

            $email = trim(filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL));
            $password = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);
            if (!$email || !$password) {
                $response = ["success" => false, "message" => "Email and password are required"];
            } else {
                $response = $userAuth->login($email, $password);
            }
            break;
        case 'register':
            $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
            $phone = filter_input(INPUT_POST, 'phone', FILTER_SANITIZE_STRING);
            $email = trim(filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL));
            $password = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);
            $role = filter_input(INPUT_POST, 'role', FILTER_SANITIZE_STRING);
            
            if (!$name || !$phone || !$email || !$password || !$role) {
                $response = ["success" => false, "message" => "All fields are required"];
            } else {
                $response = $userAuth->register($name, $phone, $password, $email, $role);
            }
            break;
        case 'forgotPassword':
            $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
            $response = $userAuth->initiatePasswordReset($email);
            break;
        case 'resetPassword':
            $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
            $password = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);
            $confirm = filter_input(INPUT_POST, 'confirm_password', FILTER_UNSAFE_RAW);
            if (!$token || !$password || !$confirm) {
                $response = ["success" => false, "message" => "All fields are required"];
            } elseif ($password !== $confirm) {
                $response = ["success" => false, "message" => "Passwords do not match"];
            } else {
                $response = $userAuth->completePasswordReset($token, $password);
            }
            break;
            
        case 'logout':
            $response = $userAuth->logout();
            break;
            
                case 'getGoogleUrl':
            try {
                $googleUrl = $userAuth->getGoogleLoginUrl();
                $response = ["success" => true, "url" => $googleUrl];
            } catch (Exception $e) {
                error_log('Error in getGoogleUrl action: ' . $e->getMessage());
                $response = ["success" => false, "message" => "Could not generate Google login URL. Please check server logs."];
            }
            break;
            
        default:
            $response = ["success" => false, "message" => "Invalid action"];
    }
    
    // Return JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}