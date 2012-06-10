# Create your views here.

from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings
from openwitness.main.forms import LoginForm
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.contrib.auth import logout


def login_user(request):
    form = None
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = request.POST['username']
            email = request.POST['user_email']
            password = request.POST['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    context = {
                        'page_title': 'Welcome to %s' % settings.PROJECT_NAME
                    }
                    return render_to_response("main/welcome.html", context,
                            context_instance=RequestContext(request))
                else:
                    context = {
                            'error_message': 'User is not activated!',
                            'page_title': 'Login Page'
                        }
                    return render_to_response("main/login.html", context,
                        context_instance=RequestContext(request))
            else:
                context = {
                    'error_message': 'Error occured at the user authentication',
                    'page_title': 'Login Page'
                }
                return render_to_response("main/login.html", context,
                    context_instance=RequestContext(request))
        else:
            context = {
            'form': form,
            'page_title': 'Login Page'
            }
            return render_to_response("main/login.html", context,
                context_instance=RequestContext(request))
    else:
        form = LoginForm()

        context = {
            'form': form,
            'page_title': 'Login Page'
        }
        return render_to_response("main/login.html", context,
            context_instance=RequestContext(request))

def logout_user(request):
    logout(request)
    return HttpResponseRedirect(reverse('login_page'))

def welcome(request):
    context = {
        'page_title': 'Welcome to %s' % settings.PROJECT_NAME
    }
    if request.user.is_authenticated():
        return render_to_response("main/welcome.html", context,
            context_instance=RequestContext(request))
    else:
        return HttpResponseRedirect(reverse('login_page'))
