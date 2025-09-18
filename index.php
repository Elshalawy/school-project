<?php
require_once 'csrf_token.php';
$csrf_token = generateToken();

// Prevent caching of the page
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>School Portal - Login & Register</title>
    <!-- Bootstrap CSS -->
    <link href="./libraries/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="./frontend/style.css">
    <!-- Custom Auth JS -->
    <script src="assets/js/auth.js" defer></script>
    <!-- Show alerts container -->
    <div id="alertContainer" class="position-fixed top-0 end-0 p-3" style="z-index: 1100;" aria-live="polite" role="alert"></div>
</head>
<body>
    <div class="container-fluid p-0">
        <div class="row g-0 min-vh-100">
            <!-- Left side form section -->
            <div class="col-md-6 d-flex align-items-center justify-content-center p-4">
                <div class="auth-form-wrapper">
                    <!-- Login Form -->
                    <div class="form-box active shadow rounded p-4 bg-white" id="login-form">
                        <h2 class="h3 mb-3 fw-bold">Login to Your Account</h2>
                        <p class="text-muted mb-4">Welcome back! Please enter your details to access your school portal</p>
                        
                        <form action="user.php" method="post" id="loginForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="action" value="login">
                            <div class="mb-3">
                                <label class="form-label" for="login-email">Email Address</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                    <input type="email" class="form-control" id="login-email" name="email" 
                                       placeholder="Enter your email" required
                                       autocomplete="username"
                                       aria-describedby="emailHelp">
                                <div id="emailHelp" class="visually-hidden">Enter your registered email address</div>
                                </div>
                            </div>
                            <div class="mb-3">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <label class="form-label mb-0" for="login-password">Password</label>
                                    <button class="text-primary border-0 rounded-3 small text-decoration-none" data-bs-toggle="modal" data-bs-target="#forgot-password-modal">
                                        Forgot password?
                                    </button>
                                </div>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                    <input type="password" class="form-control" id="login-password" name="password" 
                                       placeholder="Enter your password" required
                                       autocomplete="current-password"
                                       aria-describedby="passwordHelp">
                                <div id="passwordHelp" class="visually-hidden">Enter your account password</div>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100 mb-3">
                                Sign In
                            </button>
                        </form>
                        <div class="position-relative my-4">
                            <hr>
                            <p class="text-center position-absolute top-50 start-50 translate-middle bg-white px-3 text-muted small">
                                Or continue with
                            </p>
                        </div>              
                        <div class="d-grid gap-2 mb-4">
                            <button type="button" class="btn btn-outline-danger" onclick="handleGoogleAuth('login')">
                                <i class="fab fa-google me-2"></i> Sign in with Google
                            </button>
                        </div>
                        <?php if (isset($_GET['error'])): ?>
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            <?php echo htmlspecialchars($_GET['error']); ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>
                        <?php endif; ?>
                        <p class="text-center mb-0">
                            Don't have an account? 
                            <button style="border:none;border-radius:9px;" class="text-primary text-decoration-none" onclick="toggleForm('register')">Sign up</button>
                        </p>
                    </div>

                    <!-- Register Form -->
                    <div class="form-box shadow-lg rounded-3 p-4 bg-white" id="register-form">
                        <div class="text-center mb-4">
                            <h2 class="h3 fw-bold text-primary">Create Your Account</h2>
                            <p class="text-muted">Join our school community and start your educational journey</p>
                        </div>
                        <form action="user.php" method="post" id="registerForm" class="needs-validation" novalidate>
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="action" value="register">
                            <!-- Name Field -->
                            <div class="mb-4">
                                <label for="register-name" class="form-label fw-medium">Full Name</label>
                                <div class="input-group has-validation">
                                    <span class="input-group-text bg-light"><i class="fas fa-user text-muted"></i></span>
                                    <input type="text" 
                                           class="form-control form-control-lg py-2" 
                                           id="register-name" 
                                           name="name" 
                                           placeholder="John Doe" 
                                           required
                                           autocomplete="name"
                                           pattern="[A-Za-z\s]{2,50}"
                                           title="Name should only contain letters and spaces having(2-50 characters)">
                                    <div class="invalid-feedback">
                                        Please enter a valid name (2-50 characters, letters only)
                                    </div>
                                </div>
                                <div class="form-text text-muted small mt-1">Enter your full legal name</div>
                            </div>
                            
                            <!-- Email Field -->
                            <div class="mb-4">
                                <label for="register-email" class="form-label fw-medium">Email Address</label>
                                <div class="input-group has-validation">
                                    <span class="input-group-text bg-light"><i class="fas fa-envelope text-muted"></i></span>
                                    <input type="email" 
                                           class="form-control form-control-lg py-2" 
                                           id="register-email" 
                                           name="email" 
                                           placeholder="john@example.com" 
                                           required
                                           autocomplete="email"
                                           pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$">
                                    <div class="invalid-feedback">
                                        Please enter a valid email address
                                    </div>
                                </div>
                                <div class="form-text text-muted small mt-1">We'll never share your email with anyone else</div>
                            </div>
                            
                            <!-- Phone Number Field -->
                            <div class="mb-4">
                                <label for="register-phone" class="form-label fw-medium">Phone Number</label>
                                <div class="input-group has-validation">
                                    <span class="input-group-text bg-light"><i class="fas fa-phone text-muted"></i></span>
                                    <input type="tel" 
                                           class="form-control form-control-lg py-2" 
                                           id="register-phone" 
                                           name="phone" 
                                           placeholder="1234567890" 
                                           required
                                           autocomplete="tel"
                                           pattern="[0-9]{10,15}">
                                    <div class="invalid-feedback">
                                        Please enter a valid phone number (10-15 digits)
                                    </div>
                                </div>
                                <div class="form-text text-muted small mt-1">No spaces or special characters</div>
                            </div>
                            
                            <!-- Password Field -->
                            <div class="mb-4">
                                <label for="register-password" class="form-label fw-medium">Password</label>
                                <div class="input-group has-validation">
                                    <span class="input-group-text bg-light"><i class="fas fa-lock text-muted"></i></span>
                                    <input type="password" 
                                           class="form-control form-control-lg py-2" 
                                           id="register-password" 
                                           name="password" 
                                           placeholder="Create a strong password" 
                                           required
                                           autocomplete="new-password"
                                           minlength="8"
                                           pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}">
                                    <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <div class="invalid-feedback">
                                        Password must be at least 8 characters and include uppercase, lowercase, number, and special character
                                    </div>
                                </div>
                                <div class="progress mt-2" style="height: 4px;">
                                    <div class="progress-bar password-strength" id="password-strength" role="progressbar" style="width: 0%"></div>
                                </div>
                                <div id="passwordHelp" class="form-text text-muted small mt-1">
                                    Use 8+ characters with a mix of letters, numbers & symbols
                                </div>
                            </div>
                            <!-- Role Selection -->
                            <div class="mb-4">
                                <label for="role" class="form-label fw-medium">Select Your Role</label>
                                <select class="form-select form-select-lg py-2" id="role" name="role" required>
                                    <option value="" disabled selected>Choose your role</option>
                                    <option value="student">👨‍🎓 Student</option>
                                    <option value="teacher">👩‍🏫 Teacher</option>
                                    <option value="parent">👨‍👩‍👧‍👦 Parent/Guardian</option>
                                </select>
                                <div class="invalid-feedback">
                                    Please select a role
                                </div>
                            </div>
                            
                            <!-- Submit Button -->
                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-primary btn-lg py-2 fw-medium">
                                    <span class="d-flex align-items-center justify-content-center">
                                        <span>Create Account</span>
                                        <i class="fas fa-arrow-right ms-2"></i>
                                    </span>
                                </button>
                            </div>
                        </form>
                        
                        <!-- Social Login Divider -->
                        <div class="position-relative my-4">
                            <hr class="my-4">
                            <div class="divider-content bg-white px-3 position-absolute top-50 start-50 translate-middle">
                                <span class="text-muted small">Or register with</span>
                            </div>
                        </div>
                        
                        <!-- Social Login Buttons -->
                        <div class="d-grid gap-3 mb-4">
                            <button type="button" onclick="handleGoogleAuth('register')" class="btn btn-outline-danger d-flex align-items-center justify-content-center py-2" 
                                    >
                                <i class="fab fa-google me-2"></i>
                                <span>Continue with Google</span>
                            </button>
                        </div>
                        
                        <!-- Login Link -->
                        <p class="text-center mb-0 text-muted">
                            Already have an account? 
                            <a href="#" class="text-primary text-decoration-none fw-medium" onclick="toggleForm('login')">
                                Sign in
                            </a>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Right side hero section -->
            <div class="col-md-6 bg-auth-hero d-flex align-items-center text-white p-5">
                <div>
                    <h1 class="display-4 fw-bold mb-4">Find Your Perfect Educational Journey</h1>
                    <p class="lead mb-4">Join thousands of students, teachers, and parents who have found their ideal learning environment through our comprehensive school portal platform.</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Forgot Password Modal -->
    <div class="modal fade" id="forgot-password-modal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header border-0">
                    <h5 class="modal-title">Reset Your Password</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p class="text-muted mb-4">Enter your Email and we'll help you reset your password</p>
                    
                    <form action="user.php" method="post" id="forgotPasswordForm">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token?>">
                        <input type="hidden" name="action" value="forgotPassword">
                        <div class="mb-4">
                            <label class="form-label" for="reset-email">Email</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                <input type="email" class="form-control" id="reset-email" name="email" 
                                       placeholder="Enter your registered Email" required
                                       autocomplete="username"
                                       pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                                       title="Please enter a valid email address"
                                       aria-describedby="resetEmailHelp">
                                <div id="resetEmailHelp" class="form-text">Enter the email associated with your account</div>
                            </div>
                        </div>
                        <div class="card bg-light mb-4">
                            <div class="card-body">
                                <h6 class="card-title">How password reset works:</h6>
                                <ol class="mb-0 small">
                                    <li>Enter your Email</li>
                                    <li>We'll send you a verification code  on Email</li>
                                    <li>Enter the code to verify your identity</li>
                                    <li>Create a new secure password</li>
                                    <li>Log in with your new password</li>
                                </ol>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary border-0 rounded-3 w-100">
                            Send Reset Code
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="./libraries/js/bootstrap.bundle.min.js"></script>
    <script>
        // Form toggle functionality with accessibility improvements
        function toggleForm(formType) {
            const loginForm = document.getElementById('login-form');
            const registerForm = document.getElementById('register-form');
            
            if (formType === 'register') {
                loginForm.classList.remove('active');
                registerForm.classList.add('active');
                // Focus on the first input in the register form for better UX
                setTimeout(() => document.getElementById('register-name').focus(), 100);
            } else {
                registerForm.classList.remove('active');
                loginForm.classList.add('active');
                // Focus on the email input in the login form for better UX
                setTimeout(() => document.getElementById('login-email').focus(), 100);
            }
        }

        // Enhanced password strength meter
        function checkPasswordStrength(password) {
            let strength = 0;
            const feedback = [];
            
            // Length check
            if (password.length >= 12) strength += 25;
            else if (password.length >= 8) strength += 15;
            else if (password.length >= 4) strength += 5;
            
            // Complexity checks
            if (password.match(/[a-z]/)) strength += 10;
            if (password.match(/[A-Z]/)) strength += 10;
            if (password.match(/[0-9]/)) strength += 10;
            if (password.match(/[^a-zA-Z0-9]/)) strength += 15;
            
            // Common password check (simplified example)
            const commonPasswords = ['password', '123456', 'qwerty', 'letmein'];
            if (commonPasswords.includes(password.toLowerCase())) strength = 0;
            
            // Prevent strength from exceeding 100%
            return Math.min(100, strength);
        }

        // Toggle password visibility
        function togglePasswordVisibility(inputId, button) {
            const input = document.getElementById(inputId);
            const icon = button.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }
        
        // Initialize password strength meter and form validation
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('register-password');
            const togglePasswordBtn = document.getElementById('togglePassword');
            const strengthBar = document.getElementById('password-strength');
            
            // Toggle password visibility
            if (togglePasswordBtn) {
                togglePasswordBtn.addEventListener('click', function() {
                    togglePasswordVisibility('register-password', this);
                });
            }
            
            // Password strength meter
            const strengthText = document.createElement('div');
            strengthText.className = 'password-hint mt-1 small';
            passwordInput.parentNode.insertBefore(strengthText, passwordInput.nextSibling);
            
            passwordInput.addEventListener('input', function(e) {
                const password = e.target.value;
                const strength = checkPasswordStrength(password);
                
                // Update strength bar
                strengthBar.style.width = strength + '%';
                
                // Update color and text based on strength
                let strengthTextContent = '';
                if (password.length === 0) {
                    strengthBar.style.display = 'none';
                    strengthText.textContent = '';
                    return;
                } else {
                    strengthBar.style.display = 'block';
                }
                
                if (strength < 30) {
                    strengthBar.className = 'progress-bar bg-danger password-strength';
                    strengthTextContent = 'Weak password';
                } else if (strength < 70) {
                    strengthBar.className = 'progress-bar bg-warning password-strength';
                    strengthTextContent = 'Moderate password';
                } else {
                    strengthBar.className = 'progress-bar bg-success password-strength';
                    strengthTextContent = 'Strong password';
                }
                
                // Add password hints
                const hints = [];
                if (password.length < 8) hints.push('at least 8 characters');
                if (!password.match(/[A-Z]/)) hints.push('one uppercase letter');
                if (!password.match(/[0-9]/)) hints.push('one number');
                if (!password.match(/[^a-zA-Z0-9]/)) hints.push('one special character');
                
                if (hints.length > 0) {
                    strengthTextContent += ` - Add ${hints.join(', ')}`;
                }
                
                strengthText.textContent = strengthTextContent;
            });
            
            // Initialize form validation
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    if (!form.checkValidity()) {
                        e.preventDefault();
                        e.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            });
            
            // Add aria-labels to form controls for better accessibility
            const formControls = document.querySelectorAll('input, select, button, a');
            formControls.forEach(control => {
                if (!control.hasAttribute('aria-label') && !control.getAttribute('aria-labelledby')) {
                    const label = control.labels ? control.labels[0] : null;
                    if (label) {
                        control.setAttribute('aria-labelledby', label.id || label.htmlFor);
                    } else if (control.getAttribute('placeholder')) {
                        control.setAttribute('aria-label', control.getAttribute('placeholder'));
                    }
                }
            });
        });
    </script>
</body>
</html>
<?php
// Debug output - only for development
if (isset($_POST['action']) && $_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
    error_log('Form submission: ' . print_r($_POST, true));
}
?>