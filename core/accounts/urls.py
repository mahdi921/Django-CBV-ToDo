from django.urls import path, include
from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.LoginCustomView.as_view(), name="login"),
    path("logout/", views.LogoutCustomView.as_view(), name="logout"),
    path("signup/", views.SignUpView.as_view(), name="signup"),
    path("api/v1/", include("accounts.api.v1.urls"), name="api-v1"),
    path("api/v2/", include("djoser.urls")),
    path("api/v2/", include("djoser.urls.jwt")),
    path("", include("django.contrib.auth.urls")),
]
