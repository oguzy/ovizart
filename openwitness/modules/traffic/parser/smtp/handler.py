#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import base64
import hashlib
import os.path, os
import subprocess
import email, mimetypes
import zipfile
from openwitness.modules.traffic.log.logger import Logger
from openwitness.pcap.models import Pcap

class Handler():
    def __init__(self):
        self.log = Logger("SMTP Protocol Handler", "DEBUG")
        self.log.message("SMTP protocol handler called")
        self.file_name_li = []
        self.flow = None
        self.toProcess = dict()
        self.reportRoot = None
        self.streamcounter = 1

    def get_flow_ips(self, path, file_name):
        self.reportRoot = path
        full_path = "/".join([path, file_name])
        cmd = " ".join(["tcpflow -v -r", full_path])
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=path).communicate()[1]
        result = []
        for line in output.split("\n"):
            if "new flow" in line:
                # the the created flow files are the ones that we are looking for

                ip = line.split(":")[1].strip()
                # test whether this is an smtp flow
                smtp_flow_file_path = "/".join([path, ip])
                if not self.decode_SMTP(smtp_flow_file_path):
                    continue
                self.file_name_li.append(ip)
                ip_info = ip.split("-")
                src = ip_info[0].split(".")
                dst = ip_info[1].split(".")
                src_ip = ".".join(src[:4])
                sport = int(src[4])
                dst_ip = ".".join(dst[:4])
                dport = int(dst[4])

                packet = None
                found = False
                for pcap in self.flow.pcaps:
                    # this line is required, otherwise pcap.pcakets is not returning the info
                    pcap = Pcap.objects.get(id = pcap.id)
                    for packet in pcap.packets:
                        if packet.src_ip == src_ip and packet.sport == sport and packet.dst_ip == dst_ip and packet.dport == dport:
                            packet = packet
                            found = True
                            break
                    break

                if found:
                    timestamp = packet.timestamp
                    result.append([src_ip, sport, dst_ip, dport, timestamp])
                    result.append([dst_ip, dport, src_ip, sport, timestamp])

        return result


    def set_flow(self, flow):
        self.flow = flow


    def create_process_dic(self, path):
        for f in self.file_name_li:
            info = dict()
            path = "/".join([path, f])
            info["raw"] = open(path, "r").read()
            self.toProcess[f] = info

    def save_request_response(self, upload_path):
        self.create_process_dic(upload_path)
        for f in self.file_name_li:
            # both these functions should be reviewed
            self.process_SMTP(f)
            self.report_SMTP(f)

    def process_SMTP(self, aFile):
        a = False
        b = False
        for i in self.toProcess[aFile]['raw']:

            if a and i.startswith("MAIL FROM"):
                a = False
            if b and i == ".":
                b = False

            if a:
                self.toProcess[aFile]['logindata'].append(i)
            if b:
                self.toProcess[aFile]['msgdata'].append(i)

            if i == "AUTH LOGIN":
                a = True
                self.toProcess[aFile]['logindata'] = []
            if i == "DATA":
                b = True
                self.toProcess[aFile]['msgdata'] = []
            if i.startswith("MAIL FROM:"):
                self.toProcess[aFile]['msg_from'] = i[11:]
            if i.startswith("RCPT TO:"):
                self.toProcess[aFile]['rcpt_to'] = i[9:]

    def report_SMTP(self, aFile):
        self.log.message("Found SMTP Session data at %s" % (aFile))

        if self.toProcess[aFile].has_key("logindata"):
            self.log.message("SMTP AUTH Login: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][0])))
            self.log.message("SMTP AUTH Password: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][1])))
        if self.toProcess[aFile].has_key('msg_from'):
            self.log.message("SMTP MAIL FROM: %s"%(self.toProcess[aFile]['msg_from']))
        if self.toProcess[aFile].has_key("rcpt_to"):
            self.log.message("SMTP RCPT TO: %s"%(self.toProcess[aFile]['rcpt_to']))
        if self.toProcess[aFile].has_key('msgdata'):
            self.streamcounter += 1
            if not os.path.exists(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter))):
                os.makedirs(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter)))

            x = "\r\n".join(self.toProcess[aFile]['msgdata'])
            msg = email.message_from_string(x)
            f = open(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), "%s.msg"%(aFile)), "w")
            f.write(x)
            f.close()
            self.log.message("Found email Messages")
            self.log.message(" - Writing to file: %s"%(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), "%s.msg"%(aFile))))
            self.log.message(" - MD5 of msg: %s"%(hashlib.md5(x).hexdigest()))
            counter = 1
            # The great docs at http://docs.python.org/library/email-examples.html
            # show this easy way of breaking up a mail msg
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                filename = part.get_filename()
                if not filename:
                    ext = mimetypes.guess_extension(part.get_content_type())
                    if not ext:
                        ext = '.bin'
                    filename = 'part-%03d%s' % (counter, ext)
                part_data = part.get_payload(decode=True)
                part_hash = hashlib.md5()
                part_hash.update(part_data)
                self.log.message("   - Found Attachment" )
                self.log.message("     - Writing to filename: %s "%( os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), filename)))
                f = open(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), filename), "wb")
                f.write(part_data)
                f.close()
                self.log.message("     - Type of Attachement: %s"%(part.get_content_type()))
                self.log.message("     - MDS of Attachement: %s"%(part_hash.hexdigest()))
                if filename.endswith(".zip") or filename.endswith(".docx"):
                    self.log.message("       - ZIP Archive attachment extracting")
                    if not os.path.exists(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), "%s.unzipped"%(filename))):
                        os.makedirs(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), "%s.unzipped"%(filename)))
                    zfp = os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), "%s.unzipped"%(filename))
                    zf = zipfile.ZipFile(os.path.join(self.reportRoot, "smtp-messages", str(self.streamcounter), filename))
                    for name in zf.namelist():
                        try:
                            (path,fname) = os.path.split(os.path.join(zfp, name))
                            os.makedirs(path)
                            f = open(os.path.join(path, fname), 'wb')
                            data = zf.read(name)
                            f.write(data)
                            self.log.message(" Found file")
                            self.log.message(" Writing to filename: %s"%(os.path.join(path, fname)))
                            self.log.message(" Type of file: %s"%(mimetypes.guess_type(os.path.join(path, fname))[0]))
                            self.log.message(" MDS of File: %s"%(hashlib.md5(data).hexdigest()))
                        except Exception, ex:
                            self.log.message(ex)


    def decode_SMTP(self, i):
        f = open(i, "r")
        line = f.readline()
        if line.startswith("EHLO") or line.startswith("HELO"):
            f.close()
            return True
        f.close()
        return False




