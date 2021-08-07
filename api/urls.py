from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from rest_framework.authtoken.views import obtain_auth_token

from apiapp.viewback import (subjectView, homeView, oneGameView, loginView,
                             logoutView, createGameView,
                             updateGameView, deleteGameView
)
from apiapp.views import (
    TestUser, UserRegister,
    getSubject, createSubject, ApiSubjectListView,
    accountProperiesView, updateAccountView,
    ObtainAuthTokenView, getGames, putGame, postGame,
    ChangePasswordView, VerificationView, PasswordTokenCheckAPI,
    RequestPasswordResetEmail, SetNewPasswordReset, logaoutapi
)

urlpatterns = [
    # Back
    path('admin/', admin.site.urls),
    
    path('', homeView),
    path('subject/', subjectView),
    path('onegame/<one>/', oneGameView, name='onegame'),
    path('login/', loginView, name='login_back'),
    path('logout/', logoutView, name='logout_back'),
    path('creategame/', createGameView, name='create_game'),
    path('updategame/<id>/', updateGameView, name='update_game'),
    path('deletegame/<id>/', deleteGameView, name='delete_game'),
    
    # Api
    # path('loginapi/', obtain_auth_token),
    # path('authapi/', include('djoser.urls')), #logout --destroy token
    # path('authapi/', include('djoser.urls.authtoken')),
    path('logoutapi/', logaoutapi),
    path('loginapi/', ObtainAuthTokenView.as_view()),
    path('register/', UserRegister.as_view()),
    path('changepassword/', ChangePasswordView.as_view()),
    path('get_user/', accountProperiesView),
    path('get_user/update/', updateAccountView),
    path('testuser/', TestUser.as_view()),
    
    path('getsubject/<slug>/', getSubject),
    path('createsubject/', createSubject),
    path('listsubject/', ApiSubjectListView.as_view()),
    
    path('getgames/', getGames),
    path('putgame/<id>/', putGame),
    path('postgame/', postGame),
    
    path('activate/<uidb64>/<token>/', VerificationView.as_view(), name='activate'),
    
    path('request_reset_email/', RequestPasswordResetEmail.as_view(), name='request_reset_email'),
    path('password_reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password_reset_confirm'),
    path('password_reset_complete/', SetNewPasswordReset.as_view(), name='password_reset_complete'),

]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)