from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.contrib.auth import get_user_model


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