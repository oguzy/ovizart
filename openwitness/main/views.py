# Create your views here.

from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings


def welcome(request):
    context = {
        'page_title': 'Welcome to %s' % settings.PROJECT_NAME
    }
    if request.user.is_authenticated():
        return render_to_response("main/main.html", context,
            context_instance=RequestContext(request))
    else:
        return render_to_response("main/welcome.html",
            context_instance=RequestContext(request, context))
