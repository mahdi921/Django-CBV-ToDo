/* Task & Assignment Management Functions */

// Fetch Tasks
app.fetchTasks = async function () {
    try {
        const tasks = await this.api('/tasks/api/v1/task/', 'GET');
        this.state.tasks = tasks;
        this.renderTasks();

        // Update stats
        const completed = tasks.filter(t => t.completed).length;
        const total = tasks.length;
        const stats = document.getElementById('task-stats');
        if (stats) {
            stats.textContent = `${completed} of ${total} tasks completed`;
        }
    } catch (error) {
        this.showToast('Failed to fetch tasks', 'error');
        console.error(error);
    }
};

// Render Tasks
app.renderTasks = function () {
    const tasksList = document.getElementById('tasks-list');
    if (!tasksList) return;

    if (this.state.tasks.length === 0) {
        tasksList.innerHTML = `
            <div style="text-align: center; padding: 4rem; color: var(--text-muted)">
                <p style="font-size: 1.25rem; margin-bottom: 0.5rem;">No tasks yet</p>
                <p>Create your first task to get started!</p>
            </div>
        `;
        return;
    }

    tasksList.innerHTML = this.state.tasks.map(task => {
        const createdTime = this.formatRelativeTime(task.created_date);
        const updatedTime = this.formatRelativeTime(task.updated_date);
        const assignmentsHTML = task.assignments && task.assignments.length > 0
            ? task.assignments.map(assignment => `
                <div class="assignment-item ${assignment.completed ? 'completed' : ''}">
                    <input type="checkbox" class="assignment-checkbox"
                           ${assignment.completed ? 'checked' : ''}
                           onchange="app.toggleAssignment(${assignment.id}, event.target.checked)">
                    <span class="assignment-text">${assignment.description}</span>
                    <button class="assignment-delete" onclick="app.deleteAssignment(${assignment.id}, event)">×</button>
                </div>
            `).join('')
            : '<div class="assignment-empty">No sub-tasks yet</div>';

        return `
            <div class="task-card ${task.completed ? 'completed' : ''}">
                <input type="checkbox" class="task-checkbox"
                       ${task.completed ? 'checked' : ''}
                       onchange="app.toggleTask(${task.id}, event.target.checked)">
                <div class="task-content">
                    <div class="task-title">${task.title}</div>
                    <div class="task-meta">
                        <span>Created ${createdTime}</span>
                        <span>•</span>
                        <span>Updated ${updatedTime}</span>
                    </div>
                    <div class="assignments-section" id="assignments-${task.id}">
                        <div class="assignments-header">
                            <h4>Sub-tasks</h4>
                            <button class="add-assignment-btn" onclick="app.showAddAssignmentModal(${task.id})">
                                + Add
                            </button>
                        </div>
                        <div class="assignments-list">${assignmentsHTML}</div>
                    </div>
                </div>
                <div class="task-actions">
                    <button class="icon-btn expand" id="expand-${task.id}"
                            onclick="app.toggleTaskExpand(${task.id}, event)">▼</button>
                    <button class="icon-btn" onclick="app.showDeleteConfirmModal(${task.id}, '${task.title.replace(/'/g, "\\'")}')">🗑️</button>
                </div>
            </div>
        `;
    }).join('');
};

// Create Task
app.createTask = async function (title) {
    if (!title || !title.trim()) return;

    try {
        await this.api('/tasks/api/v1/task/', 'POST', { title: title.trim() });
        this.showToast('Task created!', 'success');
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to create task', 'error');
        console.error(error);
    }
};

// Toggle Task
app.toggleTask = async function (id, completed) {
    try {
        await this.api(`/tasks/api/v1/task/${id}/`, 'PATCH', { completed });
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to update task', 'error');
        console.error(error);
    }
};

// Delete Task
app.deleteTask = async function (id) {
    try {
        await this.api(`/tasks/api/v1/task/${id}/`, 'DELETE');
        this.showToast('Task deleted', 'success');
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to delete task', 'error');
        console.error(error);
    }
};

// Assignment Functions
app.createAssignment = async function (taskId) {
    const descInput = document.getElementById('new-assignment-desc');
    if (!descInput || !descInput.value.trim()) {
        this.showToast('Please enter a description', 'error');
        return;
    }

    try {
        await this.api('/tasks/api/v1/assignment/', 'POST', {
            task: taskId,
            description: descInput.value.trim()
        });
        this.showToast('Sub-task added!', 'success');
        this.closeModal();
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to add sub-task', 'error');
        console.error(error);
    }
};

app.toggleAssignment = async function (assignmentId, completed) {
    try {
        await this.api(`/tasks/api/v1/assignment/${assignmentId}/`, 'PATCH', { completed });
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to update sub-task', 'error');
        console.error(error);
    }
};

app.deleteAssignment = async function (assignmentId, event) {
    event.stopPropagation();

    try {
        await this.api(`/tasks/api/v1/assignment/${assignmentId}/`, 'DELETE');
        this.showToast('Sub-task deleted', 'success');
        await this.fetchTasks();
    } catch (error) {
        this.showToast('Failed to delete sub-task', 'error');
        console.error(error);
    }
};

// Utility: Format Relative Time
app.formatRelativeTime = function (dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    if (diffSec < 60) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHour < 24) return `${diffHour}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    return date.toLocaleDateString();
};
