# from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model

# from captcha.fields import CaptchaField

User = get_user_model()


class CustomLoginForm(AuthenticationForm):
    """
    adding captcha field to the login form
    """

    # captcha = CaptchaField()


class UserRegistrationForm(UserCreationForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """

    # captcha = CaptchaField()

    class Meta:
        model = User
        fields = ("email", "password1", "password2")
