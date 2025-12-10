from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView, PasswordResetView, PasswordResetConfirmView, PasswordResetDoneView, PasswordResetCompleteView
from django.views.generic import CreateView, TemplateView
from django.urls import reverse_lazy
from django.contrib.messages.views import SuccessMessageMixin
from . import forms
from django.contrib import messages

# Login View
class CustomLoginView(LoginView):
    template_name = "accounts/login.html"
    form_class = forms.CustomLoginForm
    redirect_authenticated_user = True
    
    def get_success_url(self):
        return reverse_lazy("todo:dashboard")

# Logout View
class CustomLogoutView(LogoutView):
    next_page = reverse_lazy("accounts:login")

# Register View
class RegisterView(SuccessMessageMixin, CreateView):
    template_name = "accounts/register.html"
    form_class = forms.UserRegistrationForm
    success_url = reverse_lazy("accounts:login")
    success_message = "Account created successfully! Please log in."

# Password Change View (Authenticated)
class CustomPasswordChangeView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'accounts/change_password.html'
    success_url = reverse_lazy('todo:dashboard')
    success_message = "Password changed successfully."

# Forgot Password View (Email entry)
class CustomPasswordResetView(SuccessMessageMixin, PasswordResetView):
    template_name = 'accounts/forgot_password.html'
    email_template_name = 'accounts/password_reset_email.html'
    subject_template_name = 'accounts/password_reset_subject.txt'
    form_class = forms.ThreadedPasswordResetForm
    success_url = reverse_lazy('accounts:login')
    success_message = "We've emailed you instructions for setting your password, if an account exists with the email you entered."

# Password Reset Confirm View (New password entry)
class CustomPasswordResetConfirmView(SuccessMessageMixin, PasswordResetConfirmView):
    template_name = 'accounts/reset_password_confirm.html'
    success_url = reverse_lazy('accounts:login')
    success_message = "Password has been reset successfully. You can now log in."
