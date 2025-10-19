from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic import CreateView
from . import forms
from django.urls import reverse_lazy
from django.contrib import messages

# Create your views here.


class LoginCustomView(LoginView):
    template_name = "accounts/login.html"
    # fields = 'username', 'password'
    form_class = forms.CustomLoginForm
    redirect_authenticated_user = True
    next_page = reverse_lazy("todo:index")
    success_url = reverse_lazy("todo:index")


class LogoutCustomView(LogoutView):
    next_page = reverse_lazy("todo:index")


class SignUpView(CreateView):
    template_name = "accounts/signup.html"
    form_class = forms.UserRegistrationForm
    success_url = "/accounts/login/"

    def form_valid(self, form):
        messages.success(
            self.request, "Your account has been created successfully.")
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(
            self.request,
            "There was an error creating your account. Please try again.",
        )
        return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form"] = self.get_form()
        return context
