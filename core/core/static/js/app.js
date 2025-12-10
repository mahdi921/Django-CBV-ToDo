/* Core App Initialization, State Management & API Utility */

// API URL determination (Docker vs Local)
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : 'http://backend:8000';

// Main Application Object
const app = {
    state: {
        token: localStorage.getItem('access_token'),
        tasks: [],
        user: null,
        isAuthenticated: !!localStorage.getItem('access_token'),
    },

    async init() {
        // Check for reset password token in URL
        const params = new URLSearchParams(window.location.search);
        if (params.has('uid') && params.has('token')) {
            return this.navigate('reset-password-confirm');
        }

        if (this.state.token) {
            this.state.isAuthenticated = true;
            this.loadDashboard();
        } else {
            this.navigate('login');
        }
    },

    async api(endpoint, method = 'GET', body = null) {
        const headers = {
            'Content-Type': 'application/json',
        };

        if (this.state.token) {
            headers['Authorization'] = `Bearer ${this.state.token}`;
        }

        try {
            const response = await fetch(API_URL + endpoint, {
                method,
                headers,
                body: body ? JSON.stringify(body) : null
            });

            if (response.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                this.state.token = null;
                this.state.isAuthenticated = false;
                this.navigate('login');
                throw new Error('Session expired. Please login again.');
            }

            const data = await response.json();

            if (!response.ok) {
                throw data;
            }

            return data;
        } catch (error) {
            if (error.message && error.message.includes('Session expired')) {
                throw error;
            }
            throw error;
        }
    },
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    app.init();

    // ESC key handler to close modals
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') app.closeModal(true);
    });
});
