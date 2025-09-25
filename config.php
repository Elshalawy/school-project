<?php
// Base URL configuration
define('BASE_URL', '/school-web/public');

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'school_web');

// Site configuration
define('SITE_NAME', 'Desouk Official Language School');
define('SITE_EMAIL', 'info@desoukschool.edu');

// Function to get the full URL for a given path
function url($path = '') {
    return rtrim(BASE_URL, '/') . '/' . ltrim($path, '/');
}

// Function to get the full filesystem path for a given file
function path($file = '') {
    return __DIR__ . '/' . ltrim($file, '/');
}
?>
