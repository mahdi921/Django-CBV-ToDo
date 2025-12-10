/* UI Utilities - Modals, Toasts */

app.showModal = function (title, content, footer = '') {
    app.closeModal(); // Close any existing

    const modalBackdrop = document.createElement('div');
    modalBackdrop.className = 'modal-backdrop show';

    // Default close button if not provided in footer/content
    const closeBtn = `<button onclick="app.closeModal()" class="icon-btn" style="position: absolute; top: 1rem; right: 1rem;">✕</button>`;

    modalBackdrop.innerHTML = `
        <div class="modal">
            ${closeBtn}
            <h2>${title}</h2>
            <div class="modal-body">${content}</div>
            ${footer ? `<div class="modal-actions">${footer}</div>` : ''}
        </div>
    `;

    document.body.appendChild(modalBackdrop);

    // Trap focus helper could go here

    // Close on click outside
    modalBackdrop.addEventListener('click', (e) => {
        if (e.target === modalBackdrop) app.closeModal();
    });
};

app.closeModal = function () {
    const modal = document.querySelector('.modal-backdrop');
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => modal.remove(), 200);
    }
};

app.showToast = function (message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast show ${type}`;
    toast.textContent = message;

    // Container?
    let container = document.getElementById('messages-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'messages-container';
        document.body.appendChild(container);
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
};

app.showAddAssignmentModal = function (taskId) {
    const content = `
        <div class="form-group">
            <input type="text" id="new-assignment-input" class="modal-input" placeholder="Sub-task details..." onkeypress="if(event.key==='Enter') app.createAssignment(${taskId})">
        </div>
        <p class="text-muted small">Press Enter to save</p>
    `;

    const footer = `
        <button class="btn btn-outline" onclick="app.closeModal()">Cancel</button>
        <button class="btn btn-primary" onclick="app.createAssignment(${taskId})">Add Sub-task</button>
    `;

    app.showModal('Add Sub-task', content, footer);
    setTimeout(() => document.getElementById('new-assignment-input').focus(), 100);
};
