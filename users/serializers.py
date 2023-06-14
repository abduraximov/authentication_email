from rest_framework import serializers
from rest_framework.fields import empty
from .models import CustomUser
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from .task import send_confirmation_code, email_checkss
from django.contrib.auth.password_validation import validate_password
from .models import CODE_VERIFIED, DONE, NEW, PHOTO_STEP
from django.core.validators import FileExtensionValidator
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework.generics import get_object_or_404
from django.contrib.auth.models import update_last_login


class SignUpSerializer(serializers.ModelSerializer):
    
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email'] = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = (
            'id',
            'auth_status',
            
        )

        extra_kwargs = {
            'auth_status': {'read_only': True, 'required': False}
        }
    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        code = user.create_verify_code()
        send_confirmation_code(user.email, code)
        print(user.email, 'code', code)
        user.save()
        return user

    def validate(self, data):
        # super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    
    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email')).lower()
        input = email_checkss(user_input)
        if input != "email":
            data = {
                "success": False,
                "message": "You must send email"
            }
            raise ValidationError(data)
        
        print("data:", data)

        return data
    
    def validate_email(self, value):
        if value and CustomUser.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bunday email royhatga olingan"
            }
            raise ValidationError(data)        
        else:
            data = value
        print(data)
        return data
    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data

class UpdateUserInformationSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            data = {
                "message": "Password confirm passwordga teng emas. Xato! "
            }
            raise ValidationError(data)
        if password:
            validate_password(password)
            validate_password(confirm_password)
        
        return data
    
    def validate_username(self, username):
        
        if len(username) < 5 or len(username) > 35:
            raise ValidationError(
                {
                    "message": "Username must be between 5 and 30 characters long. "
                }
            )
        elif username.isdigit():
            raise ValidationError(
                {
                    "message": "This username is entirely numeric. "
                }
            )
        
        elif CustomUser.objects.filter(username=username).exists():
            raise ValidationError(
                {
                    "message": "Bunday username allaqachon ro'yhatdan o'tgan. "
                }
            )

        return username            
    
    def update(self, instance, validated_data):

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.password = validated_data.get('password', instance.password)
        instance.username = validated_data.get('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password')) 
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance
    
class UpdateUserPhotoSer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif'])])
    
    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.auth_status = PHOTO_STEP
            instance.photo = photo
            instance.save()
        
        return instance
    
    def validate(self, attrs):
        user = CustomUser.objects.get(username=self.instance)
        if user.auth_status == NEW:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Siz ro'yhatdan to'liq o'tmagansiz. "
                }
            )
        return attrs
    
class LoginSerializer(serializers.Serializer):
    userinput = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def auth_validate(self, data):
        user_input = data.get('userinput')
        if email_checkss(user_input) == "email":
            users = CustomUser.objects.filter(email=user_input)
                
            if users.exists():
                username=CustomUser.objects.filter(email__exact=user_input).first().username
            else:
                raise ValidationError(
                    {
                        "success": False,
                        "message": "This credentials does not exists. "
                    }
                )
        else:
            users = CustomUser.objects.filter(username=user_input)
            if users.exists():
                username=CustomUser.objects.filter(username__iexact=user_input).first().username
            else:
                raise ValidationError(
                    {
                        "success": False,
                        "message": "This credentials does not exists. "
                    }
                )
        
        authentication_kwargs = {
            'username': username,
            'password': data['password']
        }
        print(authentication_kwargs)
        current_user = CustomUser.objects.filter(username__iexact=username).first()
        # 
        
        if current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Siz ro'yhatdan to'liq o'tmagansiz. "
                }
            )
        
        user = authenticate(**authentication_kwargs)

        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Sorry, login or password you entered is incorrect. Please check and try again. "
                }
            )
    
    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_STEP]:
            raise PermissionDenied("You haven't got allowed to login")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data
    

class LoginRefreshSerializer(TokenRefreshSerializer):
    
    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(CustomUser, id=user_id)
        update_last_login(None, user)
        return data
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        email = data.get('email')
        if email_checkss(email) != "email":
            raise ValidationError(
                {
                    "success": False,
                    "message": "E-mail kiritilishi kerak. "
                }
            )
        user = CustomUser.objects.filter(email=email)
        if not user.exists():
            raise NotFound(detail="User not found. ")
        data['user'] = user.first()
        return data

class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = CustomUser
        fields = (
            'id',
            'password',
            'confirm_password'
        )

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    "success": False,
                    "message": "Parollaringiz bir biriga to'g'ri kelmadi. "
                }
            )
        if password:
            validate_password(password)
        return data
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)

