const app = {
    state: {
        currentUser: null,
        isAuthenticated: false
    },

    init: async function () {
        console.log('TaskMaster MPA Initialized');

        // Handle global ESC key for modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') app.closeModal();
        });
    },

    // API Helper (preserved for potential AJAX needs)
    api: async function (endpoint, method = 'GET', body = null) {
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.getCsrfToken()
        };

        const config = {
            method,
            headers,
        };

        if (body) config.body = JSON.stringify(body);

        try {
            const response = await fetch(endpoint, config);
            if (!response.ok) {
                if (response.status === 401) {
                    window.location.href = '/accounts/login/';
                    return;
                }
                const data = await response.json();
                throw new Error(data.detail || 'Something went wrong');
            }
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            app.showToast(error.message, 'error');
            throw error;
        }
    },

    getCsrfToken: function () {
        return document.querySelector('[name=csrfmiddlewaretoken]')?.value ||
            document.cookie.match(/csrftoken=([^;]+)/)?.[1];
    }
};

document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
