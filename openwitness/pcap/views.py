# Create your views here.
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap import handler as PcapHandler
from openwitness.modules.traffic.flow import handler as FlowHandler

from openwitness.pcap.models import Pcap, PacketDetails

from openwitness.modules.traffic.detector.bro import handler as BroHandler

def upload(request):
    context = {
        'page_title': 'Upload your pcap file here',
        'upload_status': False
    }
    if request == "POST":
        form = UploadPcapForm(request.POST, request.FILES)
        if form.is_valid():
            file_handler = FileHandler()
            file_handler.save_file(request.FILES['file'])
            context['upload_status'] = True

            #save the file name to the db
            pcap_name = request.FILES['file']
            upload_path = file_handler.upload_dir
            pcap = Pcap(name=pcap_name, path=upload_path)
            # send the file to bro so that decide whether it has tcp or udp
            bro_handler = BroHandler()
            output = bro_handler.detect(file_handler.file_path, upload_path)
            if "tcp" in output:
                # run tcp flow extractor
                p_read_handler = PcapHandler.Handler()
                p_read_handler.open_file(file_handler.file_path)
                p_read_handler.open_pcap()

                f_handler = FlowHandler.Handler(p_read_handler)
                flow, direction = f_handler.get_tcp_flows()

                p_write_handler = PcapHandler.Handler()
                f_handler.save_flow(flow, p_write_handler, save_path=upload_path)
            #send them to bro
            # get the tcp/udp flows

            #save the returned information at the db also
            pcap.save()



    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))
