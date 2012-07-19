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

from openwitness.pcap.models import UserJSonFile
from django.utils import simplejson as json
from openwitness.modules.traffic.log.logger import Logger

from openwitness.pcap.models import FlowDetails, PacketDetails

from django.core.paginator import Paginator, InvalidPage, EmptyPage

import urllib2
import tempfile
import os


def login_user(request):
    log = Logger("Login form", "DEBUG")
    form = None
    logged = False
    if request.session.has_key('logged_in'):
        logged = True
    if logged or request.method == "POST":
        form = LoginForm(request.POST)
        if logged or form.is_valid():
            user = username = email = password = None
            if logged:
                username = request.session['username']
                email = request.session['user_email']
                password = request.session['password']
            else:
                username = request.POST['username']
                request.session['username'] = username
                email = request.POST['user_email']
                request.session['user_email'] = email
                password = request.POST['password']
                request.session['password'] = password
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    request.session['logged_in'] = True
                    user_id = request.user.id
                    url = "".join([settings.BASE_URL, "/api/rest/all_protocols/?format=json"])
                    log.message("URL: %s" % (url))
                    req = urllib2.Request(url, None)
                    opener = urllib2.build_opener()
                    f = opener.open(req)
                    json_response = json.load(f)
                    json_data = json.dumps(json_response)
                    json_dir = os.path.join(settings.PROJECT_ROOT, "json_files")
                    json_file = tempfile.NamedTemporaryFile(mode="w", dir=json_dir, delete=False)

                    user_json_file = UserJSonFile.objects.filter(user_id=user_id, json_type="summary-size")
                    if len(user_json_file) > 0:
                        user_json_file[0].delete()
                        file_path = os.path.join(settings.PROJECT_ROOT, "json_files", user_json_file[0].json_file_name)
                        try:
                            os.unlink(file_path)
                        except:
                            pass

                    file_name = os.path.basename(json_file.name)
                    # save the json data to the temporary file
                    json_file.write(json_data)
                    json_file.close()
                    user_json_file = UserJSonFile(user_id=user_id, json_type="summary-size", json_file_name=file_name)
                    user_json_file.save()
                    context = {
                        'page_title': 'Welcome to %s' % settings.PROJECT_NAME,
                        'pcap_operation': "welcome",
                        'json_file_url': os.path.join(settings.ALTERNATE_BASE_URL, "json_media", file_name),
                        'json_response': json_response
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
    if request.session.has_key('uploaded_hash'):
        del request.session['uploaded_hash']
    if request.session.has_key('uploaded_file_name'):
        del request.session['uploaded_file_name']
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


def flow_protocol_summary(request, protocol, date):
    if protocol not in ['UDP', 'TCP']:
        summary_type = "flow"
        summary_protocol = protocol
        summaries = FlowDetails.objects.filter(protocol=protocol)
    else:
        proto_dict = {'TCP': 6, 'UDP': 17}
        summary_type = "packets"
        summary_protocol = protocol
        summaries = PacketDetails.objects.filter(protocol=proto_dict[protocol])

    summary = filter(lambda x: x.timestamp.year == int(date), summaries)

    paginator = Paginator(summary, 15)
    # Make sure page request is an int. If not, deliver first page.
    try:
        page = int(request.GET.get('page', '1'))
    except ValueError:
        page = 1

    # If page request (9999) is out of range, deliver last page of results.
    try:
        page_summary = paginator.page(page)
    except (EmptyPage, InvalidPage):
        page_summary = paginator.page(paginator.num_pages)


    context = {
        'page_title': 'Protocol Summary',
        'page_summary': page_summary,
        'summary_type': summary_type,
        'summary_protocol': summary_protocol

    }
    return render_to_response("main/flow_summary.html", context,
            context_instance=RequestContext(request))