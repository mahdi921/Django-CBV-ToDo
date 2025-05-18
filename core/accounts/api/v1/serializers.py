from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


User = get_user_model()


class RegistrationSerializer(serializers.ModelSerializer):
    '''
    Serializer for user registration
    '''
    password1 = serializers.CharField(
        min_length=12,
        max_length=81,
        write_only=True,
    )

    class Meta:
        model = User
        fields = (
            'email',
            'password',
            'password1',
        )

    def validate(self, attrs):
        '''validate the password entered by the user'''
        if attrs.get('password') != attrs.get('password1'):
            raise serializers.ValidationError(
                {'password': 'Password fields did not match.'}
            )
        try:
            validate_password(password=attrs.get('password'))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError(
                {'password': list(e.messages)}
            )
        return super().validate(attrs)

    def create(self, validated_data):
        '''create the user'''
        validated_data.pop('password1', None)
        return User.objects.create_user(**validated_data)


class ActivationResendSerializer(serializers.Serializer):
    '''
    serializer for resending user activation link
    '''
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        '''validate the email entered by the user'''
        email = attrs.get('email')
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {'details': 'User with this email does not exist.'}
            )
        attrs['user'] = user_obj
        return super().validate(attrs)


class ChangePasswordSerializer(serializers.Serializer):
    '''
    serializer for changing user password
    '''
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        '''validate the password entered by the user'''
        if attrs.get('new_password') != attrs.get('confirm_password'):
            raise serializers.ValidationError(
                {'password': 'Password fields did not match.'}
            )
        try:
            validate_password(attrs.get('new_password'))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({
                'new_password': list(e.messages)
            })
        return super().validate(attrs)


class CustomAuthTokenSerializer(serializers.Serializer):
    '''
    serializer for custom auth token
    '''
    email = serializers.CharField(
        label=_('Email'),
        write_only=True,
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    def validate(self, attrs):
        '''validate the email and password entered by the user'''
        username = attrs.get('email')
        password = attrs.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
            if user.is_superuser is False:
                if user.is_verified is False:
                    msg = {'details': 'Please verify your Email first.'}
                    raise serializers.ValidationError(msg)
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    '''
    Custom serializer for obtaining JWT token
    '''

    def validate(self, attrs):
        '''
        Validate the token and return the user data
        '''
        validated_data = super().validate(attrs)
        if self.user.is_superuser is False:
            if self.user.is_verified is False:
                msg = {'details': 'Please verify your Email first.'}
                raise serializers.ValidationError(msg)
        validated_data['email'] = self.user.email
        validated_data['user_id'] = self.user.id
        return validated_data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            attrs['user'] = None
            return super().validate(attrs)

        attrs['user'] = user_obj
        return super().validate(attrs)


class ResetPasswordConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    password1 = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password1'):
            raise serializers.ValidationError({
                'detail': 'Password fields didn\'t match.'
            })
        try:
            validate_password(attrs.get('password'))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({
                'password': list(e.messages)
            })
        return super().validate(attrs)
