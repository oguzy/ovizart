# Create your views here.
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap.handler import Handler as PcapHandler
from openwitness.modules.traffic.flow.handler import Handler as FlowHandler

from openwitness.pcap.models import Flow, Pcap, PacketDetails

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
            # evey pcap file is saved as a flow container, there may or may not be flows, the pcaps colon will give the flow pcaps
            flow_file = Flow.objects.create(file_name=pcap_name, path=upload_path)
            # send the file to the defined protocol handler so that it can detect
            protocol_handler = settings.PROTOCOL_HANDLER
            package = "openwitness.modules.traffic.detector"
            module_name = ".".join([package, protocol_handler])
            # from openwitness.modules.traffic.detector.x import handler as imported_module
            imported_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
            imported_handler = imported_module.Handler()
            output = imported_handler.detect_proto(file_handler.file_path, upload_path)
            log.message("protocol detected: %s" % output)
            if "tcp" in output:
                # lets save the flow file name to the db first

                # run tcp flow extractor
                p_read_handler = PcapHandler()
                p_read_handler.open_file(file_handler.file_path)
                p_read_handler.open_pcap()

                f_handler = FlowHandler(p_read_handler)
                flow, direction = f_handler.get_tcp_flows()

                p_write_handler = PcapHandler()
                files = f_handler.save_flow(flow, p_write_handler, save_path=upload_path)

                # save the flow pcap names to the mongo db
                pcap_list = map(lambda x: Pcap.objects.create(file_name=x, path=upload_path), files.values())
                flow_file.pcaps = pcap_list
                flow_file.save()

                # now i should hook a protocol detector
                # before that i should detect the application level protocol

                for f in files.values():
                    output = imported_handler.detect_appproto(f, upload_path)
                    log.message("protocol detected: %s" % output)
                    if output.lower() == "http":
                        # by looking at the output http hook the parser related with it
                        #modules/traffic/parser/http
                        package = "openwitness.modules.traffic.parser"
                        module_name = ".".join([package, "http"])
                        # from openwitness.modules.traffic.parser.http import handler as imported_module
                        imported_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                        imported_handler = imported_module.Handler()

            #save the returned information at the db also
    else:
        form = UploadPcapForm()
        context['form'] = form

    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))
