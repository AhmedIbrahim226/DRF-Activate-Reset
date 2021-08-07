from django import forms

from .models import Subject, Game

class SubjectForm(forms.ModelForm):
	class Meta:
		model = Subject
		fields = ['name', 'content', 'slug']


class GametForm(forms.ModelForm):
	class Meta:
		model = Game
		fields = ['name', 'made_in', 'description', 'image']