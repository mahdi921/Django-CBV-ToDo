from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model

from captcha.fields import CaptchaField

User = get_user_model()


class CustomLoginForm(AuthenticationForm):
    """
    adding captcha field to the login form
    """

    captcha = CaptchaField()


class UserRegistrationForm(UserCreationForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """

    captcha = CaptchaField()

    class Meta:
        model = User
        fields = ("email", "password1", "password2", "captcha")


from django.contrib.auth.forms import PasswordResetForm
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from .api.utils import EmailThread

class ThreadedPasswordResetForm(PasswordResetForm):
    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):
        """
        Override the default send_mail to use EmailThread for asynchronous execution.
        """
        # Render the subject and email body
        subject = loader.render_to_string(subject_template_name, context)
        # Email subject *must not* contain newlines
        subject = "".join(subject.splitlines())
        body = loader.render_to_string(email_template_name, context)

        email_message = EmailMultiAlternatives(subject, body, from_email, [to_email])
        
        if html_email_template_name:
            html_email = loader.render_to_string(html_email_template_name, context)
            email_message.attach_alternative(html_email, "text/html")

        # Send using the threaded class
        EmailThread(email_message).start()
