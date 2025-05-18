from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from . import serializers
from ..utils import EmailThread
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken
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