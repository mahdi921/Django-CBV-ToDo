from django.contrib.auth.views import LoginView

# Create your views here.


class LoginCustomView(LoginView):
    template_name = 'accounts/login.html'
    fields = 'username', 'password'
    redirect_authenticated_user = True
    next_page = '/tasks/'
    success_url = '/'
