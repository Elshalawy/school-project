<?php
require_once 'user.php';

// Check if we have the authorization code
if (isset($_GET['code'])) {
    $response = $userAuth->handleGoogleCallback($_GET['code']);
    if ($response['success']) {
        // Determine if this was a login or registration
        $isRegistration = isset($response['is_registration']) && $response['is_registration'];
        $isLogin = isset($response['is_login']) && $response['is_login'];
        
        // Add success message to session for display
        $_SESSION['google_auth_message'] = $response['message'];
        $_SESSION['google_auth_type'] = $isRegistration ? 'registration' : 'login';
        
        header('Location: ../public/home.php');
        exit;
    } else {
        // Redirect back to login with error message
        header('Location: index.php?error=' . urlencode($response['message']));
        exit;
    }
} else {
    // No code received, redirect back to login
    header('Location: index.php?error=Google authentication failed');
    exit;
}