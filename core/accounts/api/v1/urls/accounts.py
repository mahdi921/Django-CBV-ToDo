from django.urls import path

# from rest_framework.authtoken.views import ObtainAuthToken

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .. import views

# this url patterns is for the User model
# and the authentication
urlpatterns = [
    path("register/", views.RegistrationApiView.as_view(), name="register"),
    path(
        "token/login/",
        views.CustomObtainAuthToken.as_view(),
        name="token-login",
    ),
    path(
        "token/logout/",
        views.CustomDiscardAuthToken.as_view(),
        name="token-logout",
    ),
    path("test-email/", views.SendTestEmail.as_view(), name="test-email"),
    path(
        "activation/confirm/<str:token>",
        views.ActivationApiView.as_view(),
        name="activation",
    ),
    path(
        "activation/resend/",
        views.ActivationResendApiView.as_view(),
        name="activation-resend",
    ),
    path(
        "change-password/",
        views.ChangePasswordApiView.as_view(),
        name="change-password",
    ),
    path(
        "reset-password/",
        views.ResetPasswordApiView.as_view(),
        name="reset-password",
    ),
    path(
        "reset-password/confirm/<str:uid>/<str:token>",
        views.ResetPasswordConfirmApiView.as_view(),
        name="reset-password-confirm",
    ),
    path("jwt/create/", TokenObtainPairView.as_view(), name="jwt-create"),
    path("jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    path("jwt/verify/", TokenVerifyView.as_view(), name="jwt-verify"),
]
