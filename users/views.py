from rest_framework.views import Response, APIView
from .serializers import ( SignUpSerializer, UpdateUserInformationSerializer, 
                          UpdateUserPhotoSer, LoginSerializer, 
                          LoginRefreshSerializer, LogoutSerializer,
                          ForgotPasswordSerializer, ResetPasswordSerializer
                        )
from .models import CustomUser
from rest_framework import generics
from rest_framework import permissions
from datetime import datetime
from rest_framework.validators import ValidationError
from rest_framework_simplejwt.views import TokenRefreshView
from .models import NEW, CODE_VERIFIED, PHOTO_STEP
from .task import send_confirmation_code
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.exceptions import NotFound
from django.core.exceptions import ObjectDoesNotExist

class SignUpApiView(APIView):
    permission_classes = [permissions.AllowAny, ]
    
    def post(self, request):
        # query = CustomUser.objects.all()
        serializer = SignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)
# class SignUpApiView(generics.CreateAPIView):
#     permission_classes = (permissions.AllowAny, )
#     queryset = CustomUser.objects.all()
#     serializer_class = SignUpSerializer
    
class VerifyApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        code = request.data.get('code')

        self.check_verify(user, code)
        return Response(
            data = {
                "success": True,
                "auth_status": user.auth_status,
                "access": user.token()["access"],
                "refresh_token": user.token()["refresh_token"]
            }
        )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        print(verifies)
        if not verifies.exists():
            data = {
                "message": "Your code wrong or expired. "
            }
            raise ValidationError(data)
        elif user.auth_status == NEW:
            verifies.update(is_confirmed=True)
            user.auth_status = CODE_VERIFIED
            user.save()

class GetNewVerify(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        self.check_verify(user)

        code = user.create_verify_code()
        send_confirmation_code(user.email, code)

        return Response(
            {
                "success": True,
                "message": "Tasdiqlash kod qayta jo'natildi. "
            }
        )

    @staticmethod
    def check_verify(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        print(verifies)
        if verifies.exists():
            data = {
                "message": "Your code is usable. "
            }
            raise ValidationError(data)     


# class UpdateUserInformationView(generics.UpdateAPIView):
#     permission_classes = (permissions.IsAuthenticated, )
#     serializer_class = UpdateUserInformationSerializer
#     http_method_names = ['patch', 'put']

    
#     def get_object(self):
#         return self.request.user
    
#     def update(self, request, *args, **kwargs):
#         super(UpdateUserInformationView, self).update(request, *args, **kwargs)
#         data = {
#             "success": True,
#             "message": "User updated successfully",
#             "auth_status": self.request.user.auth_status
#         }
#         return Response(data, status=200)
    
#     def partial_update(self, request, *args, **kwargs):
#         super(UpdateUserInformationView, self).partial_update(request, *args, **kwargs)
#         data = {
#             "success": True,
#             "message": "User updated successfully",
#             "auth_status": self.request.user.auth_status
#         }
#         return Response(data, status=200)
class UpdateUserInformationView(APIView):

    def put(self, request):
        user = CustomUser.objects.get(username=request.user.username)
        print(user.username, user.email)
        serializer = UpdateUserInformationSerializer(instance=user, data=request.data)

        if serializer.is_valid():
            serializer.save()
            print(serializer.data)
            data = {
                "success": True,
                "message": "User updated successfully. ",
                "auth_status": user.auth_status
            }
            return Response(data=data, status=200)
        return Response(data=serializer.errors, status=400)
    def patch(self, request):
        user = CustomUser.objects.get(username=request.user.username)
        serializer = UpdateUserInformationSerializer(instance=user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            print(serializer.data)
            data = {
                "success": True,
                "message": "User updated successfully. ",
                "auth_status": user.auth_status
            }
            return Response(data, status=200)
        return Response(data=serializer.errors, status=400)
    
class UpdateUserPhotoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = UpdateUserPhotoSer(instance=user, data=request.data)
        if serializer.is_valid():
            serializer.update(user, serializer.validated_data)
            return Response(
                data = {
                    "success": True,
                    "message": "Photo updated successfully. ",
                    "auth_status": user.auth_status 
                }
            )
        return Response(data=serializer.errors, status=400)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.validated_data, status=200)

# class LoginRefreshView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         serializer = LoginRefreshSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         return Response(serializer.data, status=200)

class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:    
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': "You are logged out"
            }
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)
        
class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        code = user.create_verify_code()
        send_confirmation_code(user.email, code)
        print(code)
        return Response(
            {
                "success": True,
                "message": "Tasdiqlash kodi muvaffaqiyatli yuborildi. ",
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token'],
                "user": user.auth_status,
            }, status=200
        )

class ResetPasswordView(generics.UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny, ]
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = CustomUser.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist as e:
            raise NotFound(detail="User not found")
        return Response(
            {
                "success": True,
                "message": "Parolingiz muvaffaqiyatli o'zgartirildi. ",
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token'],
            }
        )

    

