from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from . import serializers
from ..utils import EmailThread
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from mail_templated import EmailMessage, send_mail
from rest_framework.views import APIView
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import logging
from accounts.models import Profile
import jwt
from django.utils.http import urlsafe_base64_decode
from decouple import config

logger = logging.getLogger(__name__)

User = get_user_model()


class RegistrationApiView(generics.GenericAPIView):
    """API view to handle user registration."""

    serializer_class = serializers.RegistrationSerializer
    permission_classes = (~IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        """
        Handle user registration by validating the request data,
        creating a new user, and sending an activation email.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        email = serializer.validated_data["email"]
        data = {"email": email, "details": "User created successfully"}
        user_obj = get_object_or_404(User, email=email)
        token = self.get_tokens_for_user(user_obj)
        email_object = EmailMessage(
            "email/activation_email.tpl", {"token": token}, "m@m.com", [email]
        )
        EmailThread(email_object).start()
        data["details"] += "\nActivation email sent successfully"
        return Response(data, status=status.HTTP_201_CREATED)

    def get_tokens_for_user(self, user):
        """
        Generate JWT tokens for the user.
        Returns:
            str: Access token for the user.
        """
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return access


class ProfileApiView(generics.RetrieveUpdateAPIView):
    serializer_class = serializers.ProfileSeriaizer
    queryset = Profile.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj


class SendTestEmail(APIView):
    """API view to send a test email."""

    def get(self, request, *args, **kwargs):
        data = {}
        try:
            email_obj = send_mail(
                "email/hello.tpl",
                {"name": "jane"},
                "from@example.com",
                ["to@example.com"],
                fail_silently=False,
            )
            # Use send() instead of EmailThread for testing
            EmailThread(email_obj).start()
            data["details"] = "Email sent successfully"
            logger.info("Email sent successfully")
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}", exc_info=True)
            data["details"] = f"Error sending email: {str(e)}"
        return Response(data, status=status.HTTP_200_OK)


class ActivationApiView(APIView):
    """API view to handle user activation via email link."""

    permission_classes = [~IsAuthenticated]

    def get(self, request, token, *args, **kwargs):
        """Activate a user account using the token provided in the URL."""
        try:
            token = jwt.decode(token, config("SECRET_KEY"), algorithms=["HS256"])
            user_id = token.get("user_id")
        except jwt.ExpiredSignatureError:
            return Response(
                {"details": "Activation link expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except jwt.DecodeError:
            return Response(
                {"details": "Invalid activation link"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except jwt.InvalidSignatureError:
            return Response(
                {"details": "Invalid activation link"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_obj = User.objects.get(pk=user_id)
        if user_obj.is_verified:
            return Response(
                {"details": "User already activated"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_obj.is_verified = True
        user_obj.save()
        data = {"details": "User activated successfully"}
        return Response(data, status=status.HTTP_200_OK)


class ActivationResendApiView(generics.GenericAPIView):
    """API view to resend activation email to the user."""

    # This view allows authenticated users to request a new activation email
    # if they haven't activated their account yet.
    # It uses a serializer to validate the request data and sends an email
    # with a new activation token.
    serializer_class = serializers.ActivationResendSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data["user"]
        token = self.get_tokens_for_user(user_obj)
        email_object = EmailMessage(
            "email/activation_email.tpl",
            {"token": token},
            "m@m.com",
            to=[user_obj.email],
        )
        EmailThread(email_object).start()
        data = {"details": "Activation email resent successfully"}
        return Response(data, status=status.HTTP_200_OK)

    def get_tokens_for_user(self, user):
        """
        Generate JWT tokens for the user.
        Returns:
            str: Access token for the user.
        """
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return access


class ChangePasswordApiView(generics.GenericAPIView):
    """API view to handle user password change requests."""

    # This view allows authenticated users to change their password.
    # It uses a serializer to validate the request data and updates the user's
    # password if the old password is correct.
    serializer_class = serializers.ChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """gets the user object from the request."""
        # This method retrieves the user object from the request.
        # It is used to access the current authenticated user.
        object = self.request.user
        return object

    def put(self, request, *args, **kwargs):
        """Handle PUT requests to change the user's password."""
        self.object = self.get_object()
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            old_pwd = serializer.validated_data.get("old_password")
            if not self.object.check_password(old_pwd):
                return Response(
                    {"details": ["Old password is incorrect"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            self.object.set_password(serializer.validated_data.get("new_password"))
            self.object.save()
            data = {"details": "Password changed successfully"}
            return Response(data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        logger.info(f"User authenticated: {request.user.is_authenticated}")
        logger.info(f"User: {request.user}")
        data = {"details": "GET method allowed"}
        return Response(data, status=status.HTTP_200_OK)


class CustomObtainAuthToken(ObtainAuthToken):
    """
    Custom view to handle token authentication.
    """

    serializer_class = serializers.CustomAuthTokenSerializer
    permission_classes = [~IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        return Response(
            {
                "token": token.key,
                "user_id": user.pk,
                "email": user.email,
            }
        )


class CustomDiscardAuthToken(APIView):
    """
    Custom view to handle token authentication.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        data = {"details": "Token deleted successfully"}
        return Response(data, status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom view to handle JWT token authentication."""

    serializer_class = serializers.CustomTokenObtainPairSerializer


class ResetPasswordApiView(generics.GenericAPIView):
    """API view to handle password reset requests."""

    serializer_class = serializers.ResetPasswordSerializer
    permission_classes = [~IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests to prompt the user to enter their email
        for password reset.
        """
        return Response({"details": "Enter Your Email"}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests to send a password reset email to the user.
        The email contains a link with a token for resetting the password.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"details": "Email sent successfully"}, status=status.HTTP_200_OK
        )


class ResetPasswordConfirmApiView(generics.GenericAPIView):
    """API view to handle password reset confirmation."""

    serializer_class = serializers.ResetPasswordConfirmSerializer
    permission_classes = [~IsAuthenticated]
    __user_id = None
    __token = None

    def get(self, request, uid, token, *args, **kwargs):
        """
        Validate the token and user ID from the URL parameters on
        get requests.
        """
        try:
            user_id = urlsafe_base64_decode(uid).decode("utf-8")
            user = User.objects.get(pk=user_id)
            token = urlsafe_base64_decode(token).decode("utf-8")
            if not self.check_token(user, token):
                return Response(
                    {"details": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {"details": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
        self.__class__.__user_id = user_id
        self.__class__.__token = token
        return Response({"details": "Valid token"}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Handle the password reset confirmation by validating the
        provided password and resetting the user's password.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data.get("password")
        user = get_object_or_404(User, id=self.__class__.__user_id)
        if not self.check_token(user, self.__class__.__token):
            return Response(
                {"details": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(password)
        user.save()

        return Response(
            {"details": "Password reset successfully"},
            status=status.HTTP_200_OK,
        )

    def check_token(self, user, token):
        """
        Check if the token is valid for the user.
        """
        token_generator = PasswordResetTokenGenerator()
        return token_generator.check_token(user, token)
