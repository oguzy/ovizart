#!/usr/bin/env python
#-*- coding: UTF-8 -*-

class Handler():
    def __init__(self):
        self.log = Logger("SMTP Protocol Handler", "DEBUG")
        self.log.message("SMTP protocol handler called")
        self.file_name_li = []
        self.flow = None
        self.toProcess = dict()

    def get_flow_ips(self, path, file_name):
        full_path = "/".join(path, file_name)
        cmd = " ".join(["tcpflow -r -v", full_path])
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=path).communicate()[1]
        result = []
        for line in output.split("\n"):
            if "new flow" in line:
                # the the created flow files are the ones that we are looking for

                # test whether this is an smtp flow
                if not self.decode_SMTP(full_path):
                    continue

                ip = line.split(":")[1].strip()
                self.file_name_li.append(ip)
                ip_info = ip.split("-")
                src = ip_info[0].split(".")
                dst = ip_info[1].split(".")
                src_ip = ".".join(src[:4])
                sport = int(src[4])
                dst_ip = ".".join(dst[:4])
                dport = int(dst[4])

                packet = None
                for pcap in self.flow.pcaps:
                    for packet in pcap.packets:
                        if packet.src_ip == src_ip and packet.sport == sport and packet.dst_ip == dst_ip and packet.dport == dport:
                            packet = packet
                            break
                    break

                timestamp = packet.timestamp
                result.append([src_ip, sport, dst_ip, dport, timestamp], [dst_ip, dport, src_ip, sport, timestamp])

        return result


    def set_flow(self, flow):
        self.flow = flow


    def create_process_dic(self, path):
        for f in self.file_name_li:
            info = dict()
            path = "/".join([path, f])
            info["raw"] = open(path, "r").read()
            self.toProcess[f] = info

    def save_request_response(upload_path):
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
        self.log("-"* 40)
        self.log(" Report: %s"%(aFile))
        self.log("-"* 40 + "\n")
        self.log("Found SMTP Session data")
        #self.log(toProcess[aFile].keys()

        if self.toProcess[aFile].has_key("logindata"):
            self.log("SMTP AUTH Login: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][0])))
            self.log("SMTP AUTH Password: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][1])))
        if self.toProcess[aFile].has_key('msg_from'):
            self.log("SMTP MAIL FROM: %s"%(self.toProcess[aFile]['msg_from']))
        if self.toProcess[aFile].has_key("rcpt_to"):
            self.log("SMTP RCPT TO: %s"%(self.toProcess[aFile]['rcpt_to']))
        if self.toProcess[aFile].has_key('msgdata'):
            self.streamcounter += 1
            if not os.path.exists(os.path.join(self.reportRoot, "messages", str(self.streamcounter))):
                os.makedirs(os.path.join(self.reportRoot, "messages", str(self.streamcounter)))

            x = "\r\n".join(self.toProcess[aFile]['msgdata'])
            msg = email.message_from_string(x)
            f = open(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.msg"%(aFile)), "w")
            f.write(x)
            f.close()
            self.log("Found email Messages")
            self.log(" - Writing to file: %s"%(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.msg"%(aFile))))
            self.log(" - MD5 of msg: %s"%(hashlib.md5(x).hexdigest()))
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
                self.log("   - Found Attachment" )
                self.log("     - Writing to filename: %s "%( os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename)))
                f = open(os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename), "wb")
                f.write(part_data)
                f.close()
                self.log("     - Type of Attachement: %s"%(part.get_content_type()))
                self.log("     - MDS of Attachement: %s"%(part_hash.hexdigest()))
                if filename.endswith(".zip") or filename.endswith(".docx"):
                    self.log("       - ZIP Archive attachment extracting")
                    if not os.path.exists(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename))):
                        os.makedirs(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename)))
                    zfp = os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename))
                    zf = zipfile.ZipFile(os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename))
                    for name in zf.namelist():
                        try:
                            (path,fname) = os.path.split(os.path.join(zfp, name))
                            os.makedirs(path)
                        except:
                            pass
                        f = open(os.path.join(path, fname), 'wb')
                        data = zf.read(name)
                        f.write(data)
                        self.log("         - Found file")
                        self.log("           - Writing to filename: %s"%(os.path.join(path, fname)))
                        self.log("           - Type of file: %s"%(mimetypes.guess_type(os.path.join(path, fname))[0]))
                        self.log("           - MDS of File: %s"%(hashlib.md5(data).hexdigest()))

    def decode_SMTP(self, i):
        if i.startswith("EHLO") or i.startswith("HELO"):
            return True
        return False




