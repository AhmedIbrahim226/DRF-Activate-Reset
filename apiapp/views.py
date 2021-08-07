import re
import datetime, jwt

import pytz
from django.contrib import auth, messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text, smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from django.core.mail import EmailMessage
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework import permissions, status, generics, serializers, exceptions
from rest_framework.authtoken.views import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.generics import ListAPIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from rest_framework.filters import SearchFilter, OrderingFilter

from .serializer import (
	CreateUserSerializer, SubjectSerializer,
	CreateSubjectSerializer, AccountPropertiesSerializer,
	GameSerializer, CreateGameSerializer, ChangePasswordSerializer,
	SetNewPasswordResetSerailizer,
	ResetPasswordEmailRequestSerializer
)

from .models import Subject, Game




@api_view(['GET'])
@permission_classes((IsAuthenticated, ))
def getSubject(request, slug):
	
	oneSubject = Subject.objects.get(slug=slug)
	if oneSubject.user != request.user:
		return Response({'Honestly': 'You dont have the permission for view that'})
	else:
		context={}
		try:
			data = SubjectSerializer(oneSubject)
			context['data'] = data.data
			context['username'] = oneSubject.user.username
			return Response(context)
		except Subject.DoesNotExist:
			return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
# @permission_classes((IsAuthenticated, ))
def createSubject(request):
	try:
		token = request.COOKIES.get('cookieAhmed')
		payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
		user = User.objects.get(id=payload['id'])
	except jwt.ExpiredSignatureError:
		raise AuthenticationFailed('Unathenticated')
	
	serializer = CreateSubjectSerializer(data=request.data)
	if serializer.is_valid():
		name = request.data.get('name')
		serializer.save(user=user, slug=f'{name}-slug')
		
		return Response(serializer.data)
	return Response(serializer.errors)

	


class ApiSubjectListView(ListAPIView):
	queryset = Subject.objects.all()
	serializer_class = SubjectSerializer
	authentication_classes = (TokenAuthentication,)
	permission_classes = (IsAuthenticated,)
	pagination_class = PageNumberPagination
	filter_backends = (SearchFilter, OrderingFilter)
	search_fields = ('name', 'content', 'slug', 'user__username')
	

@api_view(['GET'])
# @permission_classes((IsAuthenticated, ))
def getGames(request):
	
	token = request.COOKIES.get('cookieAhmed')
	if not token:
		raise AuthenticationFailed([{'error':'Not token!'}])
	try:
		payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
	except jwt.ExpiredSignatureError:
		raise AuthenticationFailed([{'error':'Unathenticated!'}])
	
	games = Game.objects.all()
	serializer = GameSerializer(games, many=True)
	return Response(serializer.data)



@api_view(['PUT'])
# @permission_classes((IsAuthenticated, ))
def putGame(request, id):
	token = request.COOKIES.get('cookieAhmed')
	payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
	user = User.objects.get(id=payload['id'])
	
	game = Game.objects.get(id=id)
	game_solo = game.user
	
	if game_solo != user:
		return Response({'Honestly': 'You dont have the permission for view that'}, status=status.HTTP_404_NOT_FOUND)
	else:
		serializer = CreateGameSerializer(game, data=request.data)
		if serializer.is_valid():
			serializer.save()
			return Response(serializer.data)
		return Response(serializer.errors)

@api_view(['POST'])
@permission_classes((IsAuthenticated, ))
def postGame(request):
	serializer = CreateGameSerializer(data=request.data)
	if serializer.is_valid():
		serializer.save(user=request.user)
		return Response(serializer.data)
	return Response(serializer.errors)











@api_view(['GET'])
# @permission_classes((IsAuthenticated, ))
def accountProperiesView(request):
	
	token = request.COOKIES.get('cookieAhmed')
	
	if not token:
		raise AuthenticationFailed([{'error':'Not token!'}])
	try:
		payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
	except jwt.ExpiredSignatureError:
		raise AuthenticationFailed([{'error':'Unathenticated!'}])
	
	user = User.objects.get(id=payload['id'])
	serializer = AccountPropertiesSerializer(user)
	
	return Response([serializer.data])

	# try:
	# 	account = request.user
	# except User.DoesNotExist:
	# 	return Response(status=status.HTTP_404_NOT_FOUND)
	#
	# if request.method == 'GET':
	# 	serializer = AccountPropertiesSerializer(account)
	# 	return Response(serializer.data)


@api_view(['PUT'])
# @permission_classes((IsAuthenticated,))
def updateAccountView ( request ):
	# try:
	# 	account = request.user
	# except User.DoesNotExist:
	# 	return Response(status=status.HTTP_404_NOT_FOUND)
	try:
		token = request.COOKIES.get('cookieAhmed')
	except jwt.ExpiredSignatureError:
		raise AuthenticationFailed('Unathenticated!')
	
	if request.method == 'PUT':
		payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
		account = User.objects.get(id=payload['id'])
		serializer = AccountPropertiesSerializer(account, data=request.data)
		data = {}
		if serializer.is_valid():
			serializer.save()
			data['response'] = 'Account update success'
			return Response(data=data)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# perfect login Api
class ObtainAuthTokenView(APIView):
	
	authentication_classes = []
	permission_classes = []
	
	def post( self, request ):
		
		context = {}
		username = request.data['username']
		password = request.data['password']
		account = authenticate(username=username, password=password)
		
		if account:
			payload = {
				'id': account.id,
				'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
				'iat': datetime.datetime.utcnow()
			}
			token = jwt.encode(payload, 'ahmed', algorithm='HS256')
			response= Response()
			response.set_cookie(key='cookieAhmed', value=token, httponly=True)
			response.data = {
				'token': token
			}
			return response
		else:
			context['error_message'] = 'Invalid credintial'
			return Response(context, status.HTTP_400_BAD_REQUEST)
	
		# if account:
		# 	try:
		# 		token = Token.objects.get(user=account)
		# 	except Token.DoesNotExist:
		# 		token = Token.objects.create(user=account)
		# 	context['response'] = 'Successfully authenticated'
		# 	context['id'] = account.id
		# 	context['username'] = username
		# 	context['token'] = token.key
		#
		# else:
		# 	context['response'] = 'Error'
		# 	context['error_message'] = 'Invalid credintial'
		# return Response(context)




class UserRegister(APIView):
	
	def post( self, request ):
		data_user = CreateUserSerializer(data=request.data)
		
		if data_user.is_valid():
			account = data_user.save(is_active=False)
			# token = Token.objects.get(user=account).key
			token = PasswordResetTokenGenerator().make_token(account)
			current_site = get_current_site(request)
			email_body = {
				'user'  : account,
				'domain': current_site.domain,
				'id'   : urlsafe_base64_encode(force_bytes(account.id)),
				'token' : token,
			}
			link = reverse('activate', kwargs={'uidb64': email_body['id'], 'token': email_body['token']})
			
			email_subject = 'Activate your account'
			# activate_url = 'http://' + current_site.domain + link
			activate_url = 'http://localhost:3000' + link

			email = EmailMessage(email_subject,'Hi '+account.username + ', Please the link below to activate your account \n'+activate_url,
								 'blabla@colon.com',[account.email])
			email.send(fail_silently=False)
			
			# print(f'{account.username}/n, {account.email}/n, {account.pk}/n')
			return Response( {'data':data_user.data, 'token': token, 'id': email_body['id']})
		
		return Response(data_user.errors)


class VerificationView(APIView):
	def get(self, request, uidb64, token):
		try:
			id = force_text(urlsafe_base64_decode(uidb64))
			user = User.objects.get(id=id)
		
			# if user.is_active:
			# 	return redirect('login_back')
			user.is_active = True
			user.save()
			
			
			messages.success(request, 'Account activated successfully')
			# return redirect('login_back')
			return Response({'uidb64': uidb64, 'token': token})
		except Exception as ex:
			pass
		
		# return redirect('login_back')
	



# perfect change password
class ChangePasswordView(generics.UpdateAPIView):
	serializer_class = ChangePasswordSerializer
	
	# def get_object ( self ):
	# 	obj = self.request.user
	# 	return obj
	
	def update ( self, request):
		token = request.COOKIES.get('cookieAhmed')
		if not token:
			raise AuthenticationFailed('Unauthenticated!')

		
		payload = jwt.decode(token, 'ahmed', algorithms=['HS256'])
		object = User.objects.get(id=payload['id'])
		# object = self.get_object()
		serializer = self.get_serializer(data=request.data)
		
		if serializer.is_valid():
			if not object.check_password(serializer.data.get('old_password')):
				return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
			new_password = serializer.data.get('new_password')
			complexPassword = re.findall('[a-zA-Z]', new_password)
			if len(new_password) < 8:
				return Response(
						{'Error': 'Your password must contain at least 8 characters.'},
						status=status.HTTP_400_BAD_REQUEST
						)
			elif not complexPassword:
				return Response(
						{'Error': 'Your password can’t be entirely numeric.'}, status=status.HTTP_400_BAD_REQUEST
						)
			else:
				object.set_password(new_password)
				object.save()
				response = {
					'message': 'Password updated successfully',
				}
				return Response(response)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)








class RequestPasswordResetEmail(generics.GenericAPIView):
	serializer_class = ResetPasswordEmailRequestSerializer

	def post( self, request ):
		
		serializer = self.serializer_class(data=request.data)
		email = request.data['email']
		
		if User.objects.filter(email=email).exists():
			
			user = User.objects.get(email=email)
			uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
			# token = Token.objects.get(user=user).key
			token = PasswordResetTokenGenerator().make_token(user)
			current_site = get_current_site(request).domain
			relative_link = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})
			absurl = 'http://'+current_site+relative_link
			email_body = 'Hello, \n Use link below to reset your password \n'+absurl
			
			sendEmail = EmailMessage('Reset your password', email_body, None, [user.email])
			sendEmail.send(fail_silently=False)
			
		return Response({'Success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
	def get( self, request, uidb64, token ):
		try:
			id = smart_str(urlsafe_base64_decode(uidb64))
			user = User.objects.get(id=id)
			# token = Token.objects.get(user=user).key
			
			if not PasswordResetTokenGenerator().check_token(user, token):
				return Response(
						{'Error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED
						)
			return Response({'Success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status.HTTP_200_OK)

			
		except DjangoUnicodeDecodeError:
			return Response({'Error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
	

class SetNewPasswordReset(generics.GenericAPIView):
	serializer_class = SetNewPasswordResetSerailizer
	
	def patch( self, request ):
		serializer = self.serializer_class(data=request.data)
		serializer.is_valid(raise_exception=True)
		return Response({'success': True, 'message': 'Password reset success'}, status.HTTP_200_OK)




@api_view(['POST'])
def logaoutapi(request):
	response = Response()
	response.delete_cookie('cookieAhmed')
	response.data = {'message': 'success loged out'}
	return response

@permission_classes((IsAuthenticated, ))
class TestUser(APIView):
	def get( self, request ):
		print(request.user)
		return Response({"user": str(request.user)})
	