from django.db import models
from django.contrib.auth.models import User


class Subject(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	name = models.CharField(max_length=50)
	content = models.TextField(max_length=5000)
	slug = models.SlugField(max_length=100, unique=True)
	date_published = models.DateTimeField(auto_now_add=True, verbose_name='date published')
	date_updated = models.DateTimeField(auto_now=True, verbose_name='date updated')
	
	def __str__(self):
		return self.slug






	
class Game(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	name = models.CharField(max_length=50)
	made_in = models.CharField(max_length=50)
	description = models.TextField(max_length=5000)
	image = models.ImageField(upload_to='file/%y-%m-%d/')
	
	def __str__(self):
		return self.name