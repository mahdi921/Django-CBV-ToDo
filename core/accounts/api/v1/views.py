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
import logging
import jwt
from decouple import config

logger = logging.getLogger(__name__)

User = get_user_model()


class RegistrationApiView(generics.GenericAPIView):
    serializer_class = serializers.RegistrationSerializer
    permission_classes = (~IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        email = serializer.validated_data['email']
        data = {
            'email': email,
            'details': 'User created successfully'
        }
        user_obj = get_object_or_404(User, email=email)
        token = self.get_tokens_for_user(user_obj)
        email_object = EmailMessage('email/activation_email.tpl',
                                    {'token': token},
                                    'm@m.com',
                                    [email]
                                    )
        EmailThread(email_object).start()
        data['details'] += '\nActivation email sent successfully'
        return Response(data, status=status.HTTP_201_CREATED)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return access


class SendTestEmail(APIView):
    def get(self, request, *args, **kwargs):
        data = {}
        try:
            email_obj = send_mail(
                'email/hello.tpl',
                {'name': 'jane'},
                'from@example.com',
                ['to@example.com'],
                fail_silently=False,
            )
            # Use send() instead of EmailThread for testing
            EmailThread(email_obj).start()
            data['details'] = 'Email sent successfully'
            logger.info('Email sent successfully')
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}", exc_info=True)
            data['details'] = f'Error sending email: {str(e)}'
        return Response(data, status=status.HTTP_200_OK)


class ActivationApiView(APIView):
    def get(self, request, token, *args, **kwargs):
        try:
            token = jwt.decode(token, config('SECRET_KEY'),
                               algorithms=['HS256'])
            user_id = token.get('user_id')
        except jwt.ExpiredSignatureError:
            return Response({'details': 'Activation link expired'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({'details': 'Invalid activation link'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidSignatureError:
            return Response({'details': 'Invalid activation link'},
                            status=status.HTTP_400_BAD_REQUEST)
        user_obj = User.objects.get(pk=user_id)
        if user_obj.is_verified:
            return Response({'details': 'User already activated'},
                            status=status.HTTP_400_BAD_REQUEST)
        user_obj.is_verified = True
        user_obj.save()
        data = {
            'details': 'User activated successfully'
        }
        return Response(data, status=status.HTTP_200_OK)


class ActivationResendApiView(generics.GenericAPIView):
    serializer_class = serializers.ActivationResendSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data['user']
        token = self.get_tokens_for_user(user_obj)
        email_object = EmailMessage('email/activation_email.tpl',
                                    {'token': token},
                                    'm@m.com',
                                    to=[user_obj.email]
                                    )
        EmailThread(email_object).start()
        data = {
            'details': 'Activation email resent successfully'
        }
        return Response(data, status=status.HTTP_200_OK)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return access


class ChangePasswordApiView(generics.GenericAPIView):
    serializer_class = serializers.ChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self):
        object = self.request.user
        return object

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            old_pwd = serializer.validated_data.get('old_password')
            if not self.object.check_password(old_pwd):
                return Response({'details': ['Old password is incorrect']},
                                status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(
                serializer.validated_data.get('new_password')
            )
            self.object.save()
            data = {
                'details': 'Password changed successfully'
            }
            return Response(data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        logger.info(f"User authenticated: {request.user.is_authenticated}")
        logger.info(f"User: {request.user}")
        data = {
            'details': 'GET method allowed'
        }
        return Response(data, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class CustomObtainAuthToken(ObtainAuthToken):
    """
    Custom view to handle token authentication.
    """
    serializer_class = serializers.CustomAuthTokenSerializer
    permission_classes = [~IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
        })


class CustomDiscardAuthToken(APIView):
    """
    Custom view to handle token authentication.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        data = {
            'details': 'Token deleted successfully'
        }
        return Response(data, status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = serializers.CustomTokenObtainPairSerializer


class ResetPasswordApiView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordSerializer
    permission_classes = [~IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_obj = serializer.validated_data['user']

        if user_obj:
            token = self.get_tokens_for_user(user_obj)
            email_obj = EmailMessage(
                'email/password-reset.tpl',
                {'token': token},
                'm@m.com',
                to=[user_obj.email]
            )
            EmailThread(email_obj).start()

        data = {
            'details': 'Password reset email sent successfully'
        }
        return Response(data, status=status.HTTP_200_OK)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)
        return access


class ResetPasswordConfirmApiView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordConfirmSerializer
    model = User
    permission_classes = [~IsAuthenticated]
    __user_id = None

    def get(self, request, token, *args, **kwargs):
        if not token:
            return Response({'details': 'Token is required'},
                            status=status.HTTP_403_FORBIDDEN)
        try:
            token = jwt.decode(token, config('SECRET_KEY'),
                               algorithms=['HS256'])
            self.__class__.__user_id = token.get('user_id')

        except jwt.ExpiredSignatureError:
            return Response({'details': 'Token expired'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({'details': 'Invalid token decode error'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidSignatureError:
            return Response({'details': 'Invalid token signature error'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({'details': 'Invalid token error'},
                            status=status.HTTP_400_BAD_REQUEST)
        data = {
            'details': 'link is valid',
        }
        return Response(data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        user_obj = self.model.objects.get(id=self.__class__.__user_id)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if user_obj:
            user_obj.set_password(serializer.validated_data['password'])
            user_obj.save()
            self.__class__.__user_id = None
            data = {
                'details': 'Password updated successfully'
            }
            return Response(data, status=status.HTTP_204_NO_CONTENT)
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
