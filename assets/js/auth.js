
const auth = (() => {
    // Constants
    const FORM_ACTIONS = {
        REGISTER: 'register',
        LOGIN: 'login',
        RESET_PASSWORD: 'resetPassword',
        FORGOT_PASSWORD: 'forgotPassword'
    };

    const FORM_SELECTORS = {
        PASSWORD: '[name="password"]',
        EMAIL: '[name="email"]',
        PHONE: '[name="phone"]',
        NAME: '[name="name"]',
        ROLE: '[name="role"]',
        TOKEN: '[name="token"]',
        LOGIN_ID: '[name="login_id"]'
    };

    // Element getters
    const elements = {
        get forms() { return document.querySelectorAll('form'); },
        getPasswordStrengthBar: () => document.getElementById('password-strength'),
        getPasswordInput: () => document.getElementById('register-password')
    };

    // Validation rules
    const validationRules = {
        name: {
            required: true,
            minLength: 2,
            message: 'Please enter a valid name (minimum 2 characters)'
        },
        email: {
            required: true,
            pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            message: 'Please enter a valid email address'
        },
        phone: {
            required: true,
            pattern: /^\+?\d{11}$/,
            message: 'Please enter a valid 11-digit phone number'
        },
        password: {
            required: true,
            minLength: 8,
            pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/,
            message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character'
        }
    };

    // Private utility methods
    const privateMethods = {
        debounce: (func, delay) => {
            let timeoutId;
            return (...args) => {
                clearTimeout(timeoutId);
                timeoutId = setTimeout(() => func.apply(this, args), delay);
            };
        },

        setButtonState: (button, isLoading) => {
            if (!button) return;
            if (isLoading) {
                button.dataset.originalText = button.innerHTML;
                button.disabled = true;
                button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            } else {
                button.disabled = false;
                button.innerHTML = button.dataset.originalText || 'Submit';
            }
        },

        validateField: (fieldName, value, form) => {
            const rule = validationRules[fieldName];
            if (!rule) return true;

            if (rule.required && !value?.trim()) {
                publicMethods.showAlert('danger', `${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)} is required`, form);
                return false;
            }

            if (value && rule.pattern && !rule.pattern.test(value)) {
                publicMethods.showAlert('danger', rule.message, form);
                return false;
            }

            return true;
        },

        updatePasswordStrength: (password, strengthBar) => {
            if (!strengthBar) return;

            let strength = 0;
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[\d]/.test(password)) strength++;
            if (/[!@#$%^&*]/.test(password)) strength++;

            const percentage = (strength / 5) * 100;
            strengthBar.style.width = `${percentage}%`;
            strengthBar.className = 'progress-bar'; // Reset classes

            if (percentage < 40) {
                strengthBar.classList.add('bg-danger');
            } else if (percentage < 80) {
                strengthBar.classList.add('bg-warning');
            } else {
                strengthBar.classList.add('bg-success');
            }
        }
    };

    // Public methods exposed by the module
    const publicMethods = {
        handleGoogleAuth: function (action = 'login') {
            try {
                // Disable all Google auth buttons and show loading state
                const buttons = document.querySelectorAll(`button[onclick*="handleGoogleAuth"]`);
                buttons.forEach(btn => {
                    btn.dataset.originalText = btn.innerHTML;
                    btn.disabled = true;
                    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Connecting...';
                });

                // Get and validate CSRF token
                const csrfToken = this.getCsrfToken();
                if (!csrfToken) {
                    throw new Error('Security token is missing. Please refresh the page and try again.');
                }

                // Prepare the request
                const baseUrl = window.location.origin;
                const formData = new URLSearchParams();
                formData.append('action', 'getGoogleUrl');
                formData.append('type', action);
                formData.append('csrf_token', csrfToken);

                // Make the request
                fetch(`${baseUrl}/school-web/src/user.php`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: formData,
                    credentials: 'same-origin'
                })
                .then(response => {
                    if (!response.ok) {
                        return response.text().then(text => {
                            throw new Error(`HTTP error! status: ${response.status}, message: ${text}`);
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    if (!data || typeof data !== 'object') {
                        throw new Error('Invalid response from server');
                    }
                    
                    if (data.success && data.url) {
                        window.location.href = data.url;
                    } else {
                        throw new Error(data.message || 'Failed to get Google OAuth URL');
                    }
                })
                .catch(error => {
                    console.error('Google Auth error:', error);
                    const message = action === 'register' 
                        ? 'Failed to initialize Google Registration' 
                        : 'Failed to initialize Google Sign In';
                    this.showAlert('danger', `${message}. ${error.message || 'Please try again.'}`);
                })
                .finally(() => {
                    // Re-enable buttons and restore original text
                    buttons.forEach(btn => {
                        if (btn && btn.dataset.originalText) {
                            btn.disabled = false;
                            btn.innerHTML = btn.dataset.originalText;
                        }
                    });
                });

            } catch (error) {
                console.error('Google Auth initialization error:', error);
                this.showAlert('danger', `An error occurred: ${error.message || 'Please try again later.'}`);
                
                // Re-enable buttons if there was an error
                document.querySelectorAll(`button[onclick*="handleGoogleAuth"]`).forEach(btn => {
                    if (btn && btn.dataset.originalText) {
                        btn.disabled = false;
                        btn.innerHTML = btn.dataset.originalText;
                    }
                });
            }
        },

        determineFormAction: function (form) {
            const formId = form.id;
            if (formId) {
                if (formId.includes('register')) return FORM_ACTIONS.REGISTER;
                if (formId.includes('login')) return FORM_ACTIONS.LOGIN;
                if (formId.includes('reset')) return FORM_ACTIONS.RESET_PASSWORD;
                if (formId.includes('forgot')) return FORM_ACTIONS.FORGOT_PASSWORD;
            }

            const has = name => !!form.querySelector(`[name="${name}"]`);
            if (has('token') && has('password')) return FORM_ACTIONS.RESET_PASSWORD;
            if (has('name') && has('phone') && has('email') && has('password') && has('role')) return FORM_ACTIONS.REGISTER;
            if (has('password') && (has('email') || has('login_id') || has('phone'))) return FORM_ACTIONS.LOGIN;
            if (!has('password') && has('email')) return FORM_ACTIONS.FORGOT_PASSWORD;

            console.warn('Could not determine form action for:', form.id);
            return null;
        },

        validateForm: function (form) {
            const action = this.determineFormAction(form);
            let isValid = true;

            const fieldsToValidate = {
                [FORM_ACTIONS.REGISTER]: ['name', 'email', 'phone', 'password', 'role'],
                [FORM_ACTIONS.LOGIN]: ['login_id', 'password'],
                [FORM_ACTIONS.RESET_PASSWORD]: ['password'],
                [FORM_ACTIONS.FORGOT_PASSWORD]: ['email']
            };

            const fields = fieldsToValidate[action];
            if (!fields) return true; // No validation rules for this form

            fields.forEach(field => {
                const input = form.querySelector(`[name="${field}"]`);
                if (input) {
                    if (!privateMethods.validateField(field, input.value, form)) {
                        isValid = false;
                    }
                } else if (field === 'login_id') { // Special case for login
                    const loginId = form.querySelector(FORM_SELECTORS.PHONE)?.value ||
                                    form.querySelector(FORM_SELECTORS.EMAIL)?.value ||
                                    form.querySelector(FORM_SELECTORS.LOGIN_ID)?.value;
                    if (!loginId) {
                        this.showAlert('danger', 'Please enter your email or phone number', form);
                        isValid = false;
                    }
                } else if (field === 'role') {
                     const role = form.querySelector(FORM_SELECTORS.ROLE)?.value;
                     if (!role || !['student', 'teacher', 'parent'].includes(role)) {
                         this.showAlert('danger', 'Please select a valid role', form);
                         isValid = false;
                     }
                }
            });

            return isValid;
        },

        showAlert: function (type, message, container = document.body) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            alertDiv.setAttribute('role', 'alert');
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;

            const targetContainer = container.closest('.form-box') || container.closest('form') || container;
            targetContainer.insertBefore(alertDiv, targetContainer.firstChild);

            setTimeout(() => {
                const alertInstance = bootstrap?.Alert.getInstance(alertDiv);
                if (alertInstance) {
                    alertInstance.close();
                } else if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        },

        getCsrfToken: function () {
            return document.querySelector('[name="csrf_token"]')?.value || '';
        },

        submitForm: async function (form) {
            const submitButton = form.querySelector('button[type="submit"]');
            privateMethods.setButtonState(submitButton, true);

            try {
                if (!this.validateForm(form)) {
                    throw new Error('Form validation failed. Please check the fields.');
                }
                const formData = new FormData(form);
                const action = this.determineFormAction(form);
                if (!action) throw new Error('Could not determine form action');

                formData.set('action', action);
                // CSRF token is already in FormData if the field exists

                const response = await fetch('user.php', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });

                if (!response.ok) throw new Error(`Server returned ${response.status}`);

                const result = await response.json();

                if (result?.success) {
                    this.showAlert('success', result.message || 'Operation successful', form);
                    if (result.redirect) {
                        setTimeout(() => window.location.href = result.redirect, 1500);
                    }
                } else {
                    this.showAlert('danger', result.message || 'An unknown error occurred.', form);
                }
                return result;

            } catch (error) {
                console.error('Form submission error:', error);
                this.showAlert('danger', error.message || 'An error occurred. Please try again.', form);
                throw error; // Re-throw for external handling if needed
            } finally {
                privateMethods.setButtonState(submitButton, false);
            }
        },

        init: function () {
            // Attach form submit listeners
            elements.forms.forEach(form => {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    await this.submitForm(form).catch(err => console.error("Submit caught", err));
                });
            });

            // Password strength meter
            const passwordInput = elements.getPasswordInput();
            const strengthBar = elements.getPasswordStrengthBar();
            if (passwordInput && strengthBar) {
                passwordInput.addEventListener('input', privateMethods.debounce(() => {
                    privateMethods.updatePasswordStrength(passwordInput.value, strengthBar);
                }, 300));
            }

            // Expose handleGoogleAuth globally
            window.handleGoogleAuth = this.handleGoogleAuth.bind(this);
        }
    };

    return publicMethods;
})();

// Initialize the auth module on DOM load
document.addEventListener('DOMContentLoaded', () => {
    auth.init();
});
