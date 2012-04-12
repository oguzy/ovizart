#!/usr/bin/env python
# Turns a pcap file with http gzip compressed data into plain text, making it
# easier to follow.

import dpkt
import StringIO
import gzip


def parse_pcap_file(filename):
        streamcounter=0
        # Open the pcap file
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)

        conn = dict() # Connections with current buffer
        for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                        continue

                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                        continue

                tcp = ip.data

                tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)

                # Ensure these are in order! TODO change to a defaultdict
                if tupl in conn:
                        conn[ tupl ] = conn[ tupl ] + tcp.data
                else:
                        conn[ tupl ] = tcp.data

                # Try and parse what we have
                try:
                        stream = conn[ tupl ]
                        if stream[:4] == 'HTTP':
                                http = dpkt.http.Response(stream)
                                try:
                                    if http.headers['content-type'] == 'text/html':
                                        if http.headers['content-encoding'] == 'gzip':
                                            streamcounter = streamcounter + 1
                                            data = StringIO.StringIO(http.body)
                                            gzipper = gzip.GzipFile(fileobj=data)
                                            html = gzipper.read()
                                            print "content-type: %s - content-encoding: %s" % (http.headers['content-type'], http.headers['content-encoding'])
                                            #print html

                                        else:
                                            streamcounter = streamcounter + 1
                                            html = http.body
                                            print "content-type: %s - content-encoding: %s" % (http.headers['content-type'], http.headers['content-encoding'])
                                            #print html

                                        try:
                                            stream_name = "%s.stream.%s.html" % (filename, str(streamcounter)) #,".stream",streamcounter,".html")
                                            htmlfile = open(stream_name, 'w')
                                            htmlfile.write(html)
                                            htmlfile.close()
                                            print "saved into %s" % stream_name
                                            #print
                                        except:
                                            print "error opening the file and writing in it"

                                    else:
                                        #print  #http.headers['content-type']
                                        print "content-type: %s" % (http.headers['content-type'])

                                except:
                                    pass #print #"   - none fits?" #, http.headers

                                print

                        else:
                                http = dpkt.http.Request(stream)
                                print "[+] %s%s (%s)" % (http.headers['host'], http.uri, http.method)



                        # If we reached this part an exception hasn't been thrown
                        stream = stream[len(http):]
                        if len(stream) == 0:
                                del conn[ tupl ]
                        else:
                                conn[ tupl ] = stream
                except dpkt.UnpackError:
                        pass

        f.close()

if __name__ == '__main__':
        import sys
        if len(sys.argv) <= 1:
                print "%s " % sys.argv[0]
                sys.exit(2)
        parse_pcap_file(sys.argv[1])
