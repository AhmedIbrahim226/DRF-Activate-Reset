import re

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.authtoken.views import Token
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed

from .models import Subject, Game

# subject
class SubjectSerializer(serializers.ModelSerializer):
	class Meta:
		model = Subject
		fields = ['id', 'user', 'name', 'content','slug', 'date_updated']

class CreateSubjectSerializer(serializers.ModelSerializer):
	class Meta:
		model = Subject
		fields = ['name', 'content']

# Games
class GameSerializer(serializers.ModelSerializer):
	class Meta:
		model = Game
		fields = '__all__'

class CreateGameSerializer(serializers.ModelSerializer):
	class Meta:
		model = Game
		fields = ['name', 'made_in', 'description', 'image']

















# حلو اوي الريجستر api ده
class CreateUserSerializer(serializers.ModelSerializer):
	email = serializers.EmailField(required=True)
	first_name = serializers.CharField(required=True)
	last_name = serializers.CharField(required=True)
	
	class Meta:
		model = User
		fields = ['username','first_name', 'last_name', 'email', 'password']
		
		extra_kwargs = { 'password': { 'write_only': True } }
	
	def create(self, validated_data):
		password = validated_data.get('password', None)
		email = validated_data.get('email', None)
		if User.objects.filter(email=email).exists():
			raise serializers.ValidationError({'Error': 'This email allredy used'})
		truePassword = re.findall("[a-zA-Z]", password)
		if len(password) < 8:
			raise serializers.ValidationError({'ErrorPass': 'Your password must contain at least 8 characters.'})
		elif not truePassword:
			raise serializers.ValidationError({'ErrorPass': 'Your password can’t be entirely numeric.'})
		else:
			user = User.objects.create_user(**validated_data)
			return user


class AccountPropertiesSerializer(serializers.ModelSerializer):
	email = serializers.EmailField(required=True)
	class Meta:
		model = User
		fields = ['id', 'email', 'username']



class ChangePasswordSerializer(serializers.Serializer):
	model = User
	old_password = serializers.CharField(required=True, style={'input_type': 'password'})
	new_password = serializers.CharField(required=True, style={'input_type': 'password'})


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
	email = serializers.EmailField(required=True)
	class Meta:
		fields = ['email']

				
class SetNewPasswordResetSerailizer(serializers.Serializer):
	password = serializers.CharField(min_length=8, write_only=True)
	token = serializers.CharField(min_length=1, write_only=True)
	uidb64 = serializers.CharField(min_length=1, write_only=True)
	
	class Meta:
		fields = ['password', 'token', 'uidb64']
		
	def validate(self, attrs):
		try:
			password = attrs.get('password')
			token = attrs.get('token')
			uidb64 = attrs.get('uidb64')
			
			id = force_str(urlsafe_base64_decode(uidb64))
			user = User.objects.get(id=id)
			# tokenuser = Token.objects.get(user=user).key
			
			if not PasswordResetTokenGenerator().check_token(user, token):
				raise AuthenticationFailed('The reset link is invalid', 401)
			
			user.set_password(password)
			user.save()
			return user
		
		except:
			raise AuthenticationFailed('The reset link is invalid', 401)
		
		return attrs




































