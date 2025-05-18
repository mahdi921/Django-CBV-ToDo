from django.urls import path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .. import views

# this url patterns is for the User model
# and the authentication
urlpatterns = [
    path('register/', views.RegistrationApiView.as_view(), name='register'),
    path('test-email/', views.SendTestEmail.as_view(), name='test-email'),
    path('activation/confirm/<str:token>',
         views.ActivationApiView.as_view(), name='activation'),
    path('activation/resend/',
         views.ActivationResendApiView.as_view(), name='activation-resend'),
    path('change-password/',
         views.ChangePasswordApiView.as_view(), name='change-password'),
]
