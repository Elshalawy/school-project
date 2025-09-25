<?php
require_once './src/csrf_token.php';
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
    <style>
     
    </style>
    <title>School Portal - Login & Register</title>
    <!-- Bootstrap CSS -->
    <link href="./public/libraries/css/bootstrap.min.css" rel="stylesheet">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="./public/assets/styles/indexPge.css">
    <!-- Custom Auth JS -->
    <script src="./public/assets/js/auth.js" defer></script>
    <!-- Show alerts container -->
    <div id="alertContainer" class="position-fixed top-0 end-0 p-3" style="z-index: 1100;" aria-live="polite" role="alert"></div>
</head>
<body>
    <div class="container-fluid min-vh-100 d-flex align-items-center justify-content-center p-3">
        <div class="row g-0 auth-container w-100" style="max-width: 1200px;">
            <!-- Left side form section -->
            <div class="col-lg-6 p-4 p-lg-5 d-flex align-items-center">
                <div class="w-100" style="max-width: 500px; margin: 0 auto;">
                    <!-- Login Form -->
                    <div class="form-box active card shadow-sm rounded p-4 bg-white" id="login-form">
                        <h2 class="h3 mb-3 fw-bold">Login to Your Account</h2>
                        <p class="text-muted mb-4">Welcome back! Please enter your details to access your school portal</p>
                        
                        <form action="./src/user.php" method="post" id="loginForm">
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
                    <div class="form-box card shadow-sm rounded p-5 bg-white" id="register-form">
                        <div class="text-center mb-4">
                            <h2 class="h3 fw-bold text-primary">Get Started</h2>
                            <p class="text-muted">Create your account to join our community</p>
                        </div>
                        <form action="src/user.php" method="post" id="registerForm" class="needs-validation" novalidate>
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="action" value="register">
                            
                            <!-- Name Field -->
                            <div class="mb-3">
                                <label for="register-name" class="form-label">Full Name</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-user"></i></span>
                                    <input type="text" class="form-control" id="register-name" name="name" placeholder="John Doe" required autocomplete="name" pattern="[A-Za-z\s]{2,50}">
                                    <div class="invalid-feedback">Please enter a valid name.</div>
                                </div>
                            </div>
                            
                            <!-- Email Field -->
                            <div class="mb-3">
                                <label for="register-email" class="form-label">Email Address</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                    <input type="email" class="form-control" id="register-email" name="email" placeholder="john@example.com" required autocomplete="email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$">
                                    <div class="invalid-feedback">Please enter a valid email.</div>
                                </div>
                            </div>
                            
                            <!-- Phone Number Field -->
                            <div class="mb-3">
                                <label for="register-phone" class="form-label">Phone Number</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-phone"></i></span>
                                    <input type="tel" class="form-control" id="register-phone" name="phone" placeholder="1234567890" required autocomplete="tel" pattern="[0-9]{10,15}">
                                    <div class="invalid-feedback">Please enter a valid phone number.</div>
                                </div>
                            </div>
                            
                            <!-- Password Field -->
                            <div class="mb-3">
                                <label for="register-password" class="form-label">Password</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                    <input type="password" class="form-control" id="register-password" name="password" placeholder="Create a strong password" required autocomplete="new-password" minlength="8" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}">
                                    <button class="btn btn-outline-secondary" type="button" id="togglePassword"><i class="fas fa-eye"></i></button>
                                    <div class="invalid-feedback">Password must be 8+ characters and include uppercase, lowercase, number, and special character.</div>
                                </div>
                                <div class="progress mt-2" style="height: 4px;">
                                    <div class="progress-bar" id="password-strength" role="progressbar" style="width: 0%;"></div>
                                </div>
                            </div>

                            <!-- Role Selection -->
                            <div class="mb-3">
                                <label for="role" class="form-label">Select Your Role</label>
                                <select class="form-select" id="role" name="role" required>
                                    <option value="" disabled selected>Choose your role</option>
                                    <option value="student">Student</option>
                                    <option value="teacher">Teacher</option>
                                    <option value="parent">Parent/Guardian</option>
                                </select>
                                <div class="invalid-feedback">Please select a role.</div>
                            </div>
                            
                            <!-- Submit Button -->
                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-primary">Create Account</button>
                            </div>
                        </form>
                        
                        <!-- Social Login Divider -->
                        <div class="position-relative my-4">
                            <hr>
                            <div class="divider-content bg-white px-3 position-absolute top-50 start-50 translate-middle">
                                <span class="text-muted small">Or register with</span>
                            </div>
                        </div>
                        
                        <!-- Social Login Buttons -->
                        <div class="d-grid">
                            <button type="button" onclick="handleGoogleAuth('register')" class="btn btn-outline-danger">
                                <i class="fab fa-google me-2"></i>
                                <span>Continue with Google</span>
                            </button>
                        </div>
                        
                        <!-- Login Link -->
                        <p class="text-center mt-4 mb-0">
                            Already have an account? 
                            <a href="#" class="text-primary fw-medium" onclick="toggleForm('login')">Sign in</a>
                        </p>
                    </div>

                </div>
            </div>
            
            <!-- Right side hero section -->
            <div class="col-lg-6 d-none d-lg-flex hero-section position-relative overflow-hidden">
                <div class="position-absolute w-100 h-100" style="background: linear-gradient(135deg, rgba(67, 97, 238, 0.9) 0%, rgba(63, 55, 201, 0.9) 100%);">
                    <div class="position-absolute top-0 end-0 w-100 h-100" style="background: url('https://images.unsplash.com/photo-1523050854058-8df90110c9f1?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1000&q=80') center/cover; opacity: 0.08;"></div>
                </div>
                <div class="hero-content p-5 position-relative text-white" style="z-index: 1;">
                    <div class="mb-5" data-aos="fade-up">
                        <h1 class="display-5 fw-bold mb-4">Welcome to School Portal</h1>
                        <p class="lead mb-0">Empowering education through technology</p>
                    </div>
                    
                    <div class="features">
                        <div class="feature-item d-flex align-items-center mb-4" data-aos="fade-up" data-aos-delay="100">
                            <div class="feature-icon me-3 d-flex align-items-center justify-content-center" style="width: 50px; height: 50px; background: rgba(255, 255, 255, 0.2); border-radius: 12px;">
                                <i class="fas fa-graduation-cap"></i>
                            </div>
                            <div>
                                <h5 class="mb-1">For Students</h5>
                                <p class="mb-0 small">Access courses, assignments, and grades in one place</p>
                            </div>
                        </div>
                        
                        <div class="feature-item d-flex align-items-center mb-4" data-aos="fade-up" data-aos-delay="200">
                            <div class="feature-icon me-3 d-flex align-items-center justify-content-center" style="width: 50px; height: 50px; background: rgba(255, 255, 255, 0.2); border-radius: 12px;">
                                <i class="fas fa-chalkboard-teacher"></i>
                            </div>
                            <div>
                                <h5 class="mb-1">For Teachers</h5>
                                <p class="mb-0 small">Manage your classes and track student progress</p>
                            </div>
                        </div>
                        
                        <div class="feature-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="300">
                            <div class="feature-icon me-3 d-flex align-items-center justify-content-center" style="width: 50px; height: 50px; background: rgba(255, 255, 255, 0.2); border-radius: 12px;">
                                <i class="fas fa-user-friends"></i>
                            </div>
                            <div>
                                <h5 class="mb-1">For Parents</h5>
                                <p class="mb-0 small">Stay connected with your child's education</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-5 pt-4 border-top border-white-10" data-aos="fade-up" data-aos-delay="400">
                        <div class="d-flex align-items-center">
                            <div class="flex-shrink-0">
                                <i class="fas fa-shield-alt fa-2x me-3"></i>
                            </div>
                            <div>
                                <p class="small mb-0">Secure & private. We never share your data with third parties.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
                            <div>
                                <h5 class="mb-1">For Teachers</h5>
                                <p class="mb-0 small">Manage classes, assignments, and student progress</p>
                            </div>
                        </div>
                        
                        <div class="feature-item d-flex align-items-center" data-aos="fade-up" data-aos-delay="300">
                            <div class="feature-icon me-3">
                                <i class="fas fa-user-friends fa-lg"></i>
                            </div>
                            <div>
                                <h5 class="mb-1">For Parents</h5>
                                <p class="mb-0 small">Stay updated with your child's progress and school activities</p>
                            </div>
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
                    
                    <form action="src/user.php" method="post" id="forgotPasswordForm">
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
    <aside class="col-md-6 d-none d-md-flex align-items-center justify-content-center text-white p-5 hero-section bg-primary text-center">
          <h1 class="display-4 fw-bold mb-4">Find Your Perfect Educational Journey</h1>
          <p class="lead mb-4">Join thousands of students, teachers, and parents who trust our platform.</p>
        </div>
      </aside>
    <!-- Bootstrap Bundle with Popper -->
    <script src="./public/libraries/js/bootstrap.min.js"></script>
    <!-- AOS Animation -->
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
        // Initialize AOS animation library
        document.addEventListener('DOMContentLoaded', function() {
            AOS.init({
                duration: 600,
                once: true,
                offset: 100
            });
        });

        // Form toggle functionality with smooth animations
        function toggleForm(formType) {
            const loginForm = document.getElementById('login-form');
            const registerForm = document.getElementById('register-form');
            
            // Add fade out animation to current active form
            if (loginForm.classList.contains('active')) {
                loginForm.classList.remove('active');
            } else if (registerForm.classList.contains('active')) {
                registerForm.classList.remove('active');
            }
            
            // After fade out completes, switch forms
            setTimeout(() => {
                if (formType === 'login') {
                    loginForm.classList.add('active');
                    document.getElementById('login-email').focus();
                } else {
                    registerForm.classList.add('active');
                    document.getElementById('register-name').focus();
                }
            }, 300); // Match this with the CSS transition duration
            
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