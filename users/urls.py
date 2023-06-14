from django.urls import path
from .views import ( SignUpApiView, VerifyApiView, 
                    GetNewVerify, UpdateUserInformationView, 
                    UpdateUserPhotoView, LoginView, LoginRefreshView,
                    LogoutView, ForgotPasswordView, ResetPasswordView
                    )

urlpatterns = [
    path('signup/', SignUpApiView.as_view(), name="signup"),
    path('verify/', VerifyApiView.as_view(), name="verify"),
    path('reverify/', GetNewVerify.as_view(), name="reverify"),
    path('update-user/', UpdateUserInformationView.as_view(), name="update-user"),
    path('change-user-photo/', UpdateUserPhotoView.as_view(), name="change-user-photo"),
    path('login/', LoginView.as_view(), name="login"),
    path('login/refresh/', LoginRefreshView.as_view(), name="refresh"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('forgot-password/', ForgotPasswordView.as_view(), name="forgot-password"),
    path('reset-password/', ResetPasswordView.as_view(), name="reset-password")
]