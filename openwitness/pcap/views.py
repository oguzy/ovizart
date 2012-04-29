# Create your views here.
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap.handler import Handler as PcapHandler
from openwitness.modules.traffic.flow.handler import Handler as FlowHandler

from openwitness.pcap.models import Pcap, PacketDetails

from openwitness.modules.traffic.detector.bro.handler import Handler as BroHandler

from openwitness.modules.traffic.log.logger import Logger

def upload(request):
    log = Logger("Upload form", "DEBUG")
    context = {
        'page_title': 'Upload your pcap file here',
        'upload_status': False
    }
    if request.method == "POST":
        form = UploadPcapForm(request.POST, request.FILES)
        if form.is_valid():
            context['form'] = form
            file_handler = FileHandler()
            mem_file = request.FILES['pcap_file']
            log.message("file: %s" % mem_file.name)
            file_handler.save_file(mem_file)
            context['upload_status'] = True

            #save the file name to the db
            pcap_name = mem_file
            upload_path = file_handler.upload_dir
            pcap = Pcap(name=pcap_name, path=upload_path)
            # send the file to bro so that decide whether it has tcp or udp
            bro_handler = BroHandler()
            output = bro_handler.detect(file_handler.file_path, upload_path)
            log.message("protocol detected: %s" % output)
            if "tcp" in output:
                # run tcp flow extractor
                p_read_handler = PcapHandler()
                p_read_handler.open_file(file_handler.file_path)
                p_read_handler.open_pcap()

                f_handler = FlowHandler(p_read_handler)
                flow, direction = f_handler.get_tcp_flows()

                p_write_handler = PcapHandler()
                f_handler.save_flow(flow, p_write_handler, save_path=upload_path)
            #send them to bro
            # get the tcp/udp flows

            #save the returned information at the db also
            pcap.save()
    else:
        form = UploadPcapForm()
        context['form'] = form

    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))
