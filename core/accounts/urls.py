from django.urls import path, include
from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.CustomLoginView.as_view(), name="login"),
    path("logout/", views.CustomLogoutView.as_view(), name="logout"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("change-password/", views.CustomPasswordChangeView.as_view(), name="change-password"),
    path("forgot-password/", views.CustomPasswordResetView.as_view(), name="forgot-password"),
    path("reset-password/<str:uidb64>/<str:token>/", views.CustomPasswordResetConfirmView.as_view(), name="reset-password-confirm"),
    path("api/v1/", include("accounts.api.v1.urls"), name="api-v1"),
    path("api/v2/", include("djoser.urls")),
    path("api/v2/", include("djoser.urls.jwt")),
    path("", include("django.contrib.auth.urls")),
]
