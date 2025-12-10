/* Authentication Functions - Login, Register, Logout, Password Management */

// Login Handler
app.handleLogin = async function (e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');

    try {
        const data = await this.api('/accounts/api/v1/jwt/create/', 'POST', { email, password });

        localStorage.setItem('access_token', data.access);
        localStorage.setItem('refresh_token', data.refresh);
        this.state.token = data.access;
        this.state.isAuthenticated = true;

        this.showToast('Welcome back!', 'success');
        this.loadDashboard();
    } catch (error) {
        this.showToast(error.detail || 'Login failed. Please check your credentials.', 'error');
    }
};

// Register Handler
app.handleRegister = async function (e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());

    if (data.password !== data.confirm_password) {
        this.showToast('Passwords do not match', 'error');
        return;
    }

    if (data.password.length < 12) {
        this.showToast('Password must be at least 12 characters long', 'error');
        return;
    }

    if (!data.captcha_code) {
        this.showToast('Please enter the CAPTCHA code', 'error');
        return;
    }

    try {
        await this.api('/accounts/api/v1/register/', 'POST', data);
        this.showToast('Registration successful! Please check your email to activate your account.', 'success');
        setTimeout(() => this.navigate('login'), 3000);
    } catch (error) {
        let errorMessage = 'Registration failed. Please try again.';

        if (error.email) {
            errorMessage = `Email: ${error.email.join('. ')}`;
        } else if (error.password) {
            errorMessage = `Password: ${error.password.join('. ')}`;
        } else if (error.captcha_code) {
            errorMessage = 'Invalid CAPTCHA code. Please try again.';
        }

        this.showToast(error.message || errorMessage, 'error');
        // Refresh CAPTCHA on error
        this.refreshCaptcha();
    }
};

// Logout Handler
app.logout = function () {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    this.state.token = null;
    this.state.isAuthenticated = false;
    this.navigate('login');
};

// Password Management Functions
app.handleChangePassword = async function (e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const old_password = formData.get('old_password');
    const new_password = formData.get('new_password');
    const new_password1 = formData.get('new_password1');

    // Client-side validation
    if (new_password.length < 12) {
        return this.showToast('New password must be at least 12 characters long', 'error');
    }
    if (new_password !== new_password1) {
        return this.showToast('New passwords do not match', 'error');
    }

    try {
        const response = await this.api('/accounts/api/v1/change-password/', 'PUT', {
            old_password,
            new_password,
            new_password1
        });
        this.showToast('Password changed successfully!', 'success');
        e.target.reset();
        setTimeout(() => this.navigate('dashboard'), 2000);
    } catch (error) {
        // Parse detailed error from backend
        let errorMessage = 'Failed to change password';
        if (error.details) {
            if (Array.isArray(error.details)) {
                errorMessage = error.details.join('. ');
            } else {
                errorMessage = error.details;
            }
        } else if (error.old_password) {
            errorMessage = `Current password: ${error.old_password.join('. ')}`;
        } else if (error.new_password) {
            errorMessage = `New password: ${error.new_password.join('. ')}`;
        }
        this.showToast(errorMessage, 'error');
    }
};

app.handleForgotPassword = async function (e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');

    try {
        // SECURITY: Always show success message, even if email doesn't exist
        // This prevents email enumeration attacks
        await this.api('/accounts/api/v1/reset-password/', 'POST', { email });

        this.showToast(
            'If an account exists with this email, you will receive password reset instructions.',
            'success'
        );
        e.target.reset();
        setTimeout(() => this.navigate('login'), 4000);
    } catch (error) {
        // Even on error, show generic success message for security
        this.showToast(
            'If an account exists with this email, you will receive password reset instructions.',
            'success'
        );
        e.target.reset();
        setTimeout(() => this.navigate('login'), 4000);
    }
};

app.handleResetPasswordConfirm = async function (e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const password = formData.get('password');
    const password1 = formData.get('password1');

    // Client-side validation
    if (password.length < 12) {
        return this.showToast('Password must be at least 12 characters long', 'error');
    }
    if (password !== password1) {
        return this.showToast('Passwords do not match', 'error');
    }

    // Extract uid and token from URL
    const params = new URLSearchParams(window.location.search);
    const uid = params.get('uid');
    const token = params.get('token');

    if (!uid || !token) {
        return this.showToast('Invalid reset link. Please request a new one.', 'error');
    }

    try {
        await this.api(`/accounts/api/v1/reset-password/confirm/${uid}/${token}/`, 'POST', {
            password,
            password1
        });
        this.showToast('Password reset successful! You can now log in.', 'success');
        e.target.reset();
        // Clear URL parameters
        window.history.replaceState({}, document.title, window.location.pathname);
        setTimeout(() => this.navigate('login'), 2000);
    } catch (error) {
        // Parse detailed error from backend
        let errorMessage = 'Failed to reset password';
        if (error.details) {
            errorMessage = error.details;
            if (errorMessage.includes('Invalid') || errorMessage.includes('expired')) {
                errorMessage += '. Please request a new reset link.';
            }
        } else if (error.password) {
            errorMessage = `Password: ${error.password.join('. ')}`;
        }
        this.showToast(errorMessage, 'error');
    }
};

// CAPTCHA Functions
app.fetchCaptcha = async function () {
    try {
        const data = await this.api('/accounts/api/v1/captcha-refresh/', 'GET');
        const captchaImage = document.getElementById('captchaImage');
        const captchaHashkey = document.getElementById('id_captcha_hashkey');

        if (captchaImage && data.image_url) {
            captchaImage.src = API_URL + data.image_url;
        }
        if (captchaHashkey && data.key) {
            captchaHashkey.value = data.key;
        }
    } catch (error) {
        console.error('Failed to load CAPTCHA:', error);
        this.showToast('Failed to load CAPTCHA', 'error');
    }
};

app.refreshCaptcha = function () {
    this.fetchCaptcha();
    const captchaInput = document.getElementById('id_captcha_code');
    if (captchaInput) {
        captchaInput.value = '';
    }
};

// Profile Handler
app.fetchProfile = async function () {
    try {
        const profile = await this.api('/accounts/api/v1/profile/', 'GET');
        this.state.user = profile;

        const profileEmail = document.getElementById('profile-email');
        if (profileEmail) {
            profileEmail.textContent = profile.email || 'Loading...';
        }
    } catch (error) {
        console.error('Failed to fetch profile:', error);
    }
};
