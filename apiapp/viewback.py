from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.urls import reverse

from .forms import SubjectForm, GametForm
from .models import Game


def subjectView(request):
	form = SubjectForm(request.POST or None)
	if form.is_valid():
		instance = form.save(commit=False)
		instance.user = request.user
		instance.name = request.POST.get('name')
		instance.content = request.POST.get('content')
		instance.slug = request.POST.get('slug')
		instance.save()
			
	context = { 'form': form }
	return render(request, 'subject.html', context)



# Game

def homeView(request):
	if not request.user.is_authenticated:
		return redirect('login_back')
	return render(request, 'home.html', {})


def oneGameView(request, one):
	if not request.user.is_authenticated:
		return redirect('login_back')
	one = request.user
	instance = Game.objects.filter(user=one)
	context = {
		'instance': instance,
	}
	return render(request, 'getgame.html', context)

def createGameView(request):
	if not request.user.is_authenticated:
		return redirect('login_back')
	form = GametForm()
	
	if request.method == 'POST':
		form = GametForm(request.POST, request.FILES)
		if form.is_valid():
			ins = form.save(commit=False)
			ins.user = request.user
			ins.save()
			return redirect(reverse('onegame', kwargs={'one': request.user.id}))
	
	context = {
		"form": form
	}
	return render(request, 'creategame.html', context)

def updateGameView(request, id):
	if not request.user.is_authenticated:
		return redirect('login_back')
	
	try:
		game = Game.objects.get(id=id)
		
		if request.user.id == game.user.id:
			form = GametForm(instance=game)
			print(game.id, game.user.id)
			
			if request.method == 'POST':
				form = GametForm(request.POST, request.FILES, instance=game)
				if form.is_valid():
					form.save()
					return redirect(reverse('onegame', kwargs={'one': request.user.id}))
		else:
			return redirect(reverse('onegame', kwargs={'one': request.user.id}))
		
	except Game.DoesNotExist:
			return redirect(reverse('onegame', kwargs={'one': request.user.id}))
	
	context = {'form': form}
	return  render(request, 'creategame.html', context)


def deleteGameView(request, id):
	game = Game.objects.get(id=id)
	game.delete()
	return redirect(reverse('onegame', kwargs={'one': request.user.id}))




def loginView(request):
	if request.method == 'POST':
		username = request.POST.get('username')
		password = request.POST.get('password')
		user = authenticate(request, username=username, password=password)
		if user is not None:
			login(request, user)
			return redirect(reverse('onegame', kwargs={'one': request.user.id}))
		else:
			print('error login')
	return render(request, 'login.html', {})

def logoutView(request):
	logout(request)
	return redirect('login_back')