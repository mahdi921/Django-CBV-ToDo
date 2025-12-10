/* Task Management Logic */

app.handleTaskUpdate = function (taskId, data) {
    // Placeholder - usually handled by form submission in MPA
};

// Add Assignment (API)
app.createAssignment = async function (taskId) {
    const input = document.getElementById('new-assignment-input');
    const description = input.value.trim();
    if (!description) return;

    try {
        const data = await app.api('/tasks/api/v1/assignment/', 'POST', {
            task: taskId,
            description: description
        });

        // Refresh page to show new assignment (Simple MPA approach)
        window.location.reload();

        // Alternatively (Hybrid): Append to DOM
        // app.closeModal();
        // app.showToast('Assignment added', 'success');
    } catch (error) {
        console.error(error);
        app.showToast('Failed to add assignment', 'error');
    }
};

// Delete Assignment (API)
app.deleteAssignment = async function (assignmentId) {
    if (!confirm('Delete this assignment?')) return;

    try {
        await app.api(`/tasks/api/v1/assignment/${assignmentId}/`, 'DELETE');

        // Remove from DOM
        const el = document.getElementById(`assignment-${assignmentId}`);
        if (el) el.remove();

        app.showToast('Assignment deleted', 'success');
    } catch (error) {
        app.showToast('Failed to delete assignment', 'error');
    }
};

// Toggle Assignment (API)
app.toggleAssignment = async function (assignmentId, completed) {
    try {
        await app.api(`/tasks/api/v1/assignment/${assignmentId}/`, 'PATCH', {
            completed: completed
        });

        const text = document.querySelector(`#assignment-${assignmentId} .assignment-text`);
        if (completed) text.style.textDecoration = 'line-through';
        else text.style.textDecoration = 'none';

    } catch (error) {
        app.showToast('Failed to update assignment', 'error');
        // Revert checkbox
        const checkbox = document.querySelector(`#assignment-${assignmentId} .assignment-checkbox`);
        if (checkbox) checkbox.checked = !completed;
    }
};
