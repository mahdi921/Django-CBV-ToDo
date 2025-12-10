/* UI Functions - Navigation, Modals, Toasts */

// Navigation
app.navigate = function (view) {
    // Hide all views
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

    if (view === 'login') {
        document.getElementById('login-view').classList.add('active');
        document.querySelector('nav').style.display = 'none';
    } else if (view === 'register') {
        document.getElementById('register-view').classList.add('active');
        document.querySelector('nav').style.display = 'none';
        // Load CAPTCHA when showing register view
        this.fetchCaptcha();
    } else if (view === 'forgot-password') {
        document.getElementById('forgot-password-view').classList.add('active');
        document.querySelector('nav').style.display = 'none';
    } else if (view === 'reset-password-confirm') {
        document.getElementById('reset-password-confirm-view').classList.add('active');
        document.querySelector('nav').style.display = 'none';
    } else if (view === 'change-password') {
        // Require authentication
        if (!this.state.isAuthenticated) {
            return this.navigate('login');
        }
        document.getElementById('change-password-view').classList.add('active');
        document.querySelector('nav').style.display = 'flex';
    } else if (view === 'dashboard') {
        if (!this.state.isAuthenticated) {
            return this.navigate('login');
        }
        document.getElementById('dashboard-view').classList.add('active');
        document.querySelector('nav').style.display = 'flex';
        this.loadDashboard();
    }
};

app.loadDashboard = async function () {
    this.navigate('dashboard');
    await this.fetchTasks();
    await this.fetchProfile();
};

// Modal System
app.showModal = function (title, content, actions) {
    const modalContent = document.getElementById('modal-content');
    modalContent.innerHTML = `
        <h2>${title}</h2>
        <div class="modal-body">${content}</div>
        <div class="modal-actions">${actions}</div>
    `;
    document.getElementById('modal-backdrop').classList.add('show');
};

app.closeModal = function (event) {
    // Close if clicking backdrop or called programmatically
    if (!event || event.target === event.currentTarget || event === true) {
        document.getElementById('modal-backdrop').classList.remove('show');
    }
};

app.showAddTaskModal = function () {
    this.showModal(
        'Create New Task',
        `<input type="text" id="new-task-title" placeholder="What needs to be done?" 
                class="modal-input" autofocus>`,
        `<button class="btn btn-outline" onclick="app.closeModal()">Cancel</button>
         <button class="btn btn-primary" onclick="app.createTaskFromModal()">Create</button>`
    );

    // Autofocus the input
    setTimeout(() => {
        const input = document.getElementById('new-task-title');
        if (input) {
            input.focus();
            // Allow Enter key to create task
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') app.createTaskFromModal();
            });
        }
    }, 100);
};

app.createTaskFromModal = function () {
    const input = document.getElementById('new-task-title');
    if (input && input.value.trim()) {
        this.createTask(input.value);
        this.closeModal();
    }
};

app.showDeleteConfirmModal = function (taskId, taskTitle) {
    this.showModal(
        'Delete Task',
        `<p>Are you sure you want to delete "<strong>${taskTitle}</strong>"?</p>
         <p class="text-muted">This action cannot be undone.</p>`,
        `<button class="btn btn-outline" onclick="app.closeModal(true)">Cancel</button>
         <button class="btn btn-danger" onclick="app.confirmDelete(${taskId})">Delete</button>`
    );
};

app.confirmDelete = function (taskId) {
    this.deleteTask(taskId);
    this.closeModal(true);
};

app.showAddAssignmentModal = function (taskId) {
    this.showModal(
        'Add Sub-task',
        `<textarea id="new-assignment-desc" placeholder="Describe the sub-task..." 
                  class="modal-textarea" rows="3" autofocus></textarea>`,
        `<button class="btn btn-outline" onclick="app.closeModal()">Cancel</button>
         <button class="btn btn-primary" onclick="app.createAssignment(${taskId})">Add Sub-task</button>`
    );

    setTimeout(() => document.getElementById('new-assignment-desc')?.focus(), 100);
};

// Task Expand/Collapse
app.toggleTaskExpand = function (taskId, event) {
    event.stopPropagation();
    const section = document.getElementById(`assignments-${taskId}`);
    const btn = document.getElementById(`expand-${taskId}`);

    if (section && btn) {
        section.classList.toggle('show');
        btn.classList.toggle('expanded');
    }
};

// Toast Notifications
app.showToast = function (message, type = 'info') {
    const toast = document.getElementById('toast');

    // Handle multi-line messages
    toast.textContent = message;

    // Set type-specific class
    toast.className = 'toast';
    if (type) {
        toast.classList.add(type);
    }

    // Show toast
    toast.classList.add('show');

    // Auto-hide after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
};
