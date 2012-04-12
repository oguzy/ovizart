#!/opt/local/bin/python2.6
# ^ valid for scapy-2.6 package on macports
#
# Pcapline
# Timeline Generation for pcap files
#
# Wesley McGrew
# Mississippi State University National Forensics Training Center
# http://security.cse.msstate.edu/ftc
#
# wesley@mcgrewsecurity.com
# http://mcgrewsecurity.com
#

import sys
import os
import time
import re
import hashlib
import struct
from scapy.all import *

version = '0.9'
global pkt_num
global flow_num
global pcap_filename
global first_pkt_time
global first_pkt_time_set
global carve_num
flows = {}

def hex_dump(data):
	output = ''
	i = 0
	while i < len(data):
		offset = '%08X ' % i
		hex_field = ''
		ascii_field = ''
		for j in range(0,16):
			if (i+j) < len(data):
				hex_field += '%02X ' % ord(data[i+j])
				if ord(data[i+j]) > 31 and ord(data[i+j]) < 127:
					ascii_field += data[i+j]
				else:
					ascii_field += '.'
			else:
				hex_field += '   '
				ascii_field += ' '
			if j == 7:
				hex_field += ' '
				ascii_field += ' '
		output += offset + '| ' + hex_field + '| ' + ascii_field + '\n'
		i += 16
	return output

def flags_to_str(flags):
	flags_str = ''
	if flags & 0x80:
		flags_str += 'C'
	else:
		flags_str += '-'
	if flags & 0x40:
		flags_str += 'E'
	else:
		flags_str += '-'
	if flags & 0x20:
		flags_str += 'U'
	else:
		flags_str += '-'
	if flags & 0x10:
		flags_str += 'A'
	else:
		flags_str += '-'
	if flags & 0x08:
		flags_str += 'P'
	else:
		flags_str += '-'
	if flags & 0x04:
		flags_str += 'R'
	else:
		flags_str += '-'
	if flags & 0x02:
		flags_str += 'S'
	else:
		flags_str += '-'
	if flags & 0x01:
		flags_str += 'F'
	else:
		flags_str += '-'	
	return flags_str
	

def get_flow_tuple(pkt):
	src_ip = pkt.getlayer(IP).src
	dst_ip = pkt.getlayer(IP).dst
	
	if pkt.getlayer(IP).proto == 6:
		src_port = pkt.getlayer(TCP).sport
		dst_port = pkt.getlayer(TCP).dport
	elif pkt.getlayer(IP).proto == 17:
		src_port = pkt.getlayer(UDP).sport
		dst_port = pkt.getlayer(UDP).dport
	else:
		src_port = -1
		dst_port = -1
		
	return (src_ip,src_port,dst_ip,dst_port)

class Flow:
	num_pkts = 0
	flow_id = 0
	start_time = 0
	last_time = 0
	data_len = 0
	flow_tuple = ()
	protocol = ''
	dataseg_num = -1
	dataseg_host = ''
	dataseg_filename = ''
	dataseg = ''

	# Add carvers for various formats to this function. 
	# Currently, it has carvers that specifically target
	# what is required for the challenge:
	#  * HTTP GET requests
	#  * HTTP responses
	def carve_from_segment(self,data):
		global carve_num
		s = ''
		if re.search(r'^GET .*? HTTP/',data):
			s += '<li>Carved as HTTP GET request\n'
			s += '<ul>\n'
			uri = 'http://'
			m = re.search(r'Host: (.+)\n',data)
			uri += m.group(1)
			uri = uri[:len(uri)-1]
			m = re.search(r'GET (\S*) HTTP',data)
			uri += m.group(1)
			s += '  <li>URI: %s\n' % uri
			m = re.search(r'Referer: (.+)\n',data)
			if m:
				s += '  <li>Referer: %s\n' % m.group(1)
			m = re.search(r'User-Agent: (.+)\n',data)
			s += '  <li>User Agent: %s\n' % m.group(1)
			s += '</ul>\n'
			return s
		if re.search(r'Content-Length:',data):
			s += '<li>Carved as HTTP response\n'
			s += '<ul>\n'
			m = re.search(r'Content-Type: (.+)\n',data)
			s += '  <li>Content-Type: %s\n' % m.group(1)
			m = re.search(r'Content-Length: (.+)\n',data)
			s += '  <li>Content-Length: %s\n' % m.group(1)
			content_re = re.compile(r'Content-Length: .+\r\n\r\n(.*)',re.DOTALL)
			m = re.search(content_re,data)
			content = m.group(1)
			filename = 'carve%04i' % carve_num
			carve_num += 1
			fp = open('%s_output/%04i/%s' % (pcap_filename,self.flow_id,filename),'w')
			fp.write(content)
			fp.close()
			s += '  <li>Contents carved to: <a href=%s>%s</a>\n' % (filename,filename)
			s += '  <li>MD5: %s\n' % hashlib.md5(content).hexdigest()
			s += '</ul>\n'
			return s
		if (struct.unpack('<i',data[:4])[0] + 4) == len(data):
			transfer_data = data[4:]
			filename = 'carve%04i' % carve_num
			carve_num += 1
			fp = open('%s_output/%04i/%s' % (pcap_filename,self.flow_id,filename),'w')
			fp.write(transfer_data)
			fp.close()
			s += '<li>Carved as SANS Forensic Challenge malware sample file transfer\n'
			s += '<ul>\n'
			s += '  <li>Contents carved to: <a href=%s>%s</a>\n' % (filename,filename)
			s += '  <ul>\n'
			fn = '%s_output/%04i/%s' % (pcap_filename,self.flow_id,filename)
			os.system('file %s > %s.file_output' % (fn,fn))
			fp = open('%s.file_output' % fn,'r')
			file_output = fp.read()
			fp.close()
			s += '    <li>\'file\' output: <pre>%s</pre>\n' % file_output
			s += '  </ul>\n'
			s += '  <li>Size: %i\n' % len(transfer_data)
			s += '  <li>MD5: %s\n' % hashlib.md5(transfer_data).hexdigest()
			s += '</ul>\n'
		return s
	
	def add_to_segments(self,pkt,pkt_number):
		if pkt.haslayer('Raw'):
			self.data_len += len(pkt.getlayer('Raw').load)
			if self.dataseg_host == pkt.getlayer(IP).src:
				self.dataseg += pkt.getlayer(Raw).load
				self.dataseg_to_num[self.dataseg_num].append(pkt_number)
				self.num_to_dataseg[pkt_number] = self.dataseg_num
			else:
				if self.dataseg_filename != '':
					fp = open('%s_output/%04i/%s' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
					fp.write(self.dataseg)
					fp.close()
					fp = open('%s_output/%04i/%s.txt' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
					fp.write(self.dataseg)
					fp.close()
					fp = open('%s_output/%04i/%s.hex.txt' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
					fp.write(hex_dump(self.dataseg))
					fp.close()
				self.dataseg = pkt.getlayer(Raw).load
				self.dataseg_num += 1
				self.dataseg_filename = "%04i_%s" % (self.dataseg_num, pkt.getlayer(IP).src)
				self.dataseg_host = pkt.getlayer(IP).src
				self.dataseg_to_num[self.dataseg_num] = []
				self.dataseg_to_num[self.dataseg_num].append(pkt_number)
				self.num_to_dataseg[pkt_number] = self.dataseg_num
		return
	
	def flush(self):
		if self.dataseg_filename != '':
			fp = open('%s_output/%04i/%s' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
			fp.write(self.dataseg)
			fp.close()
			fp = open('%s_output/%04i/%s.txt' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
			fp.write(self.dataseg)
			fp.close()
			fp = open('%s_output/%04i/%s.hex.txt' % (pcap_filename,self.flow_id,self.dataseg_filename),'w')
			fp.write(hex_dump(self.dataseg))
			fp.close()
		return	
	
	def __init__(self, pkt, pkt_number):
		global flow_num
		global pcap_filename
		
		self.loaded_pkts = []
		self.pkt_numbers = []
		self.dataseg_to_num = {}
		self.num_to_dataseg = {}
		
		self.pkt_numbers.append(pkt_number)
		self.loaded_pkts.append(pkt)

		self.num_pkts += 1
		self.flow_id = flow_num
		os.mkdir('%s_output/%04i' % (pcap_filename,self.flow_id))
		# pcap_filename + '_output/' + str(self.flow_id))
		
		self.start_time = pkt.time
		self.last_time = pkt.time
		
		self.flow_tuple = get_flow_tuple(pkt)
		if pkt.getlayer(IP).proto == 6:
			self.protocol = 'TCP'
		elif pkt.getlayer(IP).proto == 17:
			self.protocol = 'UDP'
		
		self.add_to_segments(pkt,pkt_number)	
		
		return
	
	def save(self):
		global pcap_filename
		flow_pkts = PacketList(self.loaded_pkts)
		output_filename = '%s_output/%04i/packets.pcap' % (pcap_filename,self.flow_id)
		wrpcap(output_filename,flow_pkts)
		return	
	
	def add_pkt(self,pkt, pkt_number):
		self.loaded_pkts.append(pkt)
		self.pkt_numbers.append(pkt_number)
		self.num_pkts += 1
		self.last_time = pkt.time
		self.add_to_segments(pkt,pkt_number)
		return
	
	def packet_numbers(self):
		s = ''
		in_run = False
		first_num = True
		previous = -50
		pkt_num = 0
		
		for i in self.pkt_numbers:
			if i == previous + 1:
				in_run = True
				previous = i
				if pkt_num == len(self.pkt_numbers)-1:
					s += ' - %i' % previous
				pkt_num += 1
				continue
			else:
				if in_run == True:
					s += ' - %i' % previous
					in_run = False
				if first_num == True:
					s += '%i' % i
					first_num = False
				else:
					s += ', %i' % i
			previous = i
			pkt_num += 1
		
		return s
		
	def flow_report(self):
		global first_pkt_time
		
		s = '<tr>\n'
		s += '  <td><a href=\'%04i/index.html\'>%04i</a>\n' % (self.flow_id,self.flow_id)
		s += '  <td>%s\n' % self.protocol
		s += '  <td>%s:%i\n' % (self.flow_tuple[0],self.flow_tuple[1])
		s += '  <td>%s:%i\n' % (self.flow_tuple[2],self.flow_tuple[3])
		s += '  <td>%f\n' % (self.start_time - first_pkt_time)
		s += '  <td>%f\n' % (self.last_time - first_pkt_time)
		s += '  <td>%i\n' % self.data_len
		s += '  <td>%s\n' % self.packet_numbers()
		s += '</tr>\n'
		
		r =  '<html>\n'
		r += '<title>Flow %i Information\n' % self.flow_id
		r += '<body>\n'
		r += '<h1>Flow %i</h1>\n' % self.flow_id
		r += '<h2>Summary</h2>\n'
		r += '<ul>\n'
		r += '  <li><b>Hosts</b>\n'
		r += '  <ul>\n'
		r += '    <li>%s:%i\n' % (self.flow_tuple[0],self.flow_tuple[1])
		r += '    <li>%s:%i\n' % (self.flow_tuple[2],self.flow_tuple[3])
		r += '  </ul>\n'
		r += '  <li><b>Start time:</b> %f seconds\n' % (self.start_time - first_pkt_time)
		r += '  <li><b>Last packet sniffed time:</b> %f seconds\n' % (self.last_time - first_pkt_time)
		r += '  <li><b>Protocol</b>: %s\n' % self.protocol
		r += '  <li><b>Bytes of data:</b> %i bytes\n' % self.data_len
		r += '  <li><b>Packet #s:</b> %s\n' % self.packet_numbers()
		r += '  <li><b>.pcap of this flow:</b> <a href=packets.pcap>packets.pcap</a>\n'
		r += '</ul>\n'
		
		if self.protocol == 'UDP':
			r += '<h2>Packets List</h2>\n'
			ignore_until = -1
			for i in range(0,len(self.loaded_pkts)):
				if self.pkt_numbers[i] <= ignore_until:
					continue
				if self.pkt_numbers[i] in self.num_to_dataseg:
					r += '<h3>Data Segment</h3>\n'
					dataseg_num = self.num_to_dataseg[self.pkt_numbers[i]]
					pkt_nums = self.dataseg_to_num[dataseg_num]
					ignore_until = pkt_nums[len(pkt_nums)-1]
					src = self.loaded_pkts[i].getlayer(IP).src
					fp = open("%s_output/%04i/%04i_%s" % (pcap_filename,self.flow_id,dataseg_num,src),'r')
					data = fp.read()
					fp.close()
					r += '<table border=1>\n'
					r += '<tr>\n'
					r += '  <td><b>Packets</b>\n'
					r += '  <td><b>Start Time</b>\n'
					r += '  <td><b>Source</b>\n'
					r += '  <td><b>Destination</b>\n'
					r += '  <td><b>Data Bytes</b>\n'
					r += '</tr>\n'
					r += '<tr>\n'
					r += '  <td>%s - %s\n' % (self.pkt_numbers[i], ignore_until)
					r += '  <td>%f\n' % (self.loaded_pkts[i].time - first_pkt_time)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).src, self.loaded_pkts[i].getlayer(UDP).sport)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).dst, self.loaded_pkts[i].getlayer(UDP).dport)
					r += '  <td>%i\n' % len(data)
					r += '</tr>\n'
					r += '</table>\n'
					r += '<p>View data:\n'
					r += '<ul>\n'
					r += '  <li><a href="%04i_%s.hex.txt">Hex dump</a>\n' % (dataseg_num,src)
					r += '  <li><a href="%04i_%s.txt">View as text</a>\n' % (dataseg_num,src)
					r += '  <li><a href="%04i_%s">Raw</a>\n' % (dataseg_num,src)
					r += self.carve_from_segment(data)
					r += '</ul>\n'
		
		if self.protocol == 'TCP':
			r += '<h2>Packets and Data</h2>\n'
			need_new_table = True
			end_table = False
			ignore_until = -1
			for i in range(0,len(self.loaded_pkts)):
				if self.pkt_numbers[i] <= ignore_until:
					continue
				if self.pkt_numbers[i] in self.num_to_dataseg:
					r += '</table>\n'
					need_new_table = True
					end_table = False
					r += '<h3>Data Segment</h3>\n'
					dataseg_num = self.num_to_dataseg[self.pkt_numbers[i]]
					pkt_nums = self.dataseg_to_num[dataseg_num]
					ignore_until = pkt_nums[len(pkt_nums)-1]
					src = self.loaded_pkts[i].getlayer(IP).src
					fp = open("%s_output/%04i/%04i_%s" % (pcap_filename,self.flow_id,dataseg_num,src),'r')
					data = fp.read()
					fp.close()
					r += '<table border=1>\n'
					r += '<tr>\n'
					r += '  <td><b>Packets</b>\n'
					r += '  <td><b>Start Time</b>\n'
					r += '  <td><b>Source</b>\n'
					r += '  <td><b>Destination</b>\n'
					r += '  <td><b>Data Bytes</b>\n'
					r += '</tr>\n'
					r += '<tr>\n'
					r += '  <td>%s - %s\n' % (self.pkt_numbers[i], ignore_until)
					r += '  <td>%f\n' % (self.loaded_pkts[i].time - first_pkt_time)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).src, self.loaded_pkts[i].getlayer(TCP).sport)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).dst, self.loaded_pkts[i].getlayer(TCP).dport)
					r += '  <td>%i\n' % len(data)
					r += '</tr>\n'
					r += '</table>\n'
					r += '<p>View data:\n'
					r += '<ul>\n'
					r += '  <li><a href="%04i_%s.hex.txt">Hex dump</a>\n' % (dataseg_num,src)
					r += '  <li><a href="%04i_%s.txt">View as text</a>\n' % (dataseg_num,src)
					r += '  <li><a href="%04i_%s">Raw</a>\n' % (dataseg_num,src)
					r += self.carve_from_segment(data)
					r += '</ul>\n'
				else:
					if need_new_table:
						r += '<h3>Non-Data Packets</h3>\n'
						r += '<table border=1>\n'
						r += '<tr>\n'
						r += '  <td><b>Packet #</b>\n'
						r += '  <td><b>Time</b>\n'
						r += '  <td><b>Source</b>\n'
						r += '  <td><b>Destination</b>\n'
						r += '  <td><b>IP ID#</b>\n'
						r += '  <td><b>Sequence #</b>\n'
						r += '  <td><b>Ack #</b>\n'
						r += '  <td><b>TCP Flags</b>\n'
						r += '</tr>\n'
						need_new_table = False
						end_table = True
					r += '<tr>\n'
					r += '  <td>%i\n' % self.pkt_numbers[i]
					r += '  <td>%f\n' % (self.loaded_pkts[i].time - first_pkt_time)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).src, self.loaded_pkts[i].getlayer(TCP).sport)
					r += '  <td>%s:%i\n' % (self.loaded_pkts[i].getlayer(IP).dst, self.loaded_pkts[i].getlayer(TCP).dport)
					r += '  <td>%i\n' % self.loaded_pkts[i].getlayer(IP).id
					r += '  <td>%i\n' % self.loaded_pkts[i].getlayer(TCP).seq
					r += '  <td>%i\n' % self.loaded_pkts[i].getlayer(TCP).ack
					r += '  <td><pre>%s</pre>\n' % flags_to_str(self.loaded_pkts[i].getlayer(TCP).flags)
					r += '</tr>\n'
			if end_table:
				r += '</table>\n'
		
		r += '</body>\n'
		r += '</html>\n'
		fp = open('%s_output/%04i/index.html' % (pcap_filename,self.flow_id), 'w')
		fp.write(r)
		fp.close()
		
		return s
		
	def __lt__(self, other):
		if self.start_time < other.start_time:
			return True
		return False

# End connection class

# Callback for packet "arrival"
def pkt_handler(pkt):
	global pkt_num
	global flow_num
	global first_pkt_time
	global first_pkt_time_set
	
	if first_pkt_time_set == False:
		first_pkt_time = pkt.time
		first_pkt_time_set = True
	
	handled = False
	flow_tuple = get_flow_tuple(pkt)
	flow_tuple_backwards = (flow_tuple[2],flow_tuple[3],flow_tuple[0],flow_tuple[1])
	
	if flow_tuple in flows:
		flows[flow_tuple].add_pkt(pkt,pkt_num)
	elif flow_tuple_backwards in flows:
		flows[flow_tuple_backwards].add_pkt(pkt,pkt_num)
	else:
		flows[flow_tuple] = Flow(pkt,pkt_num)
		flow_num += 1
	
	pkt_num += 1		
	return

####### Execution starts here

pcap_filename = sys.argv[1]

print '[*] Pcapline v' + version

pkt_num = 1
flow_num = 1
first_pkt_time_set = False
carve_num = 0

try:
	os.mkdir(pcap_filename + '_output')
except:
	print '[*] Could not create output directory: %s_output' % pcap_filename
	sys.exit(1)
	
# By using the sniff() function with a callback,
# and setting store to 0, we can stream in the pcap
# rather than read the entire thing into memory at 
# once.  This'll save us some memory overhead if you 
# ever want to run this on pcaps larger than a couple
# megs ;)

print '[*] Processing pcap'
sniff(prn=pkt_handler,offline=pcap_filename,store=0)

sorted_flows = flows.values()
sorted_flows.sort()

print '[*] Generating report'
s =  '<html>\n'
s += '<title>Pcapline Output for %s\n</title>' % pcap_filename
s += '<body>\n'
s += '<h1>Pcapline Output for %s</h1>\n' % pcap_filename
s += '<h3>Notes</h3>\n'
s += '<ul>\n'
s += '  <li>Times measured in seconds elapsed since first packet captured\n'
s += '  <li>The time of first packet capture may not be the time that the capture was started\n'
s += '  <li>Packet numbers refer to the input pcap file, and are indexed\n'
s += '      starting at \'1\', to match Wireshark\'s display\n'
s += '  <li>Flows of data are sorted by start time in ascending order\n'
s += '  <li>Non-data packets that arrive in the middle of data segments (normally just ACKs) are\n'
s += '      omitted from flow reports for brevity\n'
s += '</ul>\n'
s += '<table border=1>\n'
s += '<tr>\n'
s += '  <td><b>Flow #</b>\n'
s += '  <td><b>Protocol</b>\n'
s += '  <td><b>Host 1</b>\n'
s += '  <td><b>Host 2</b>\n'
s += '  <td><b>Start Time</b>\n'
s += '  <td><b>Last Packet Time</b>\n'
s += '  <td><b>Bytes of Data</b>\n'
s += '  <td><b>Packet #s</b>\n'
s += '</tr>\n'
for f in sorted_flows:
	f.flush()
	s += f.flow_report()
	f.save()
s += '</table>\n'
s += '</body>\n'
s += '</html>\n'

fp = open(pcap_filename + '_output/index.html','w')
fp.write(s)
fp.close()
	


