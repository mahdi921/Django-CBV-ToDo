/* Authentication Logic */

// mostly handled by Django views/forms now.
// Keeping empty container or utility functions if needed.

app.validatePassword = function (password) {
    return password.length >= 8;
};
