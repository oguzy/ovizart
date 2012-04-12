# Copyright (c) 2010-2011, Mariano Graziano (graziano.mariano@gmail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are prohibited without specific prior written permission of
# the copyright holder.
#

#TODO LIST:
# 1) implement dump functions for sites, exe and pdf files
# 2) improve the code and irc traffic detection
# 3) remember to not reinvent the wheel :)

#Imports
import sys, string, socket, collections, re, os, time, urllib2
from datetime import datetime
from optparse import OptionParser
try:
	import dpkt
except ImportError:
	print "[!] ERROR: Unable to load dpkt library, please verify your installation."
	sys.exit(1)


#Initialize the key of the dictionary
class Connection:
	def __init__(self, p1, p2):
		self.p1 = p1
		self.p2 = p2

	def __cmp__(self, other):
		if ((self.p1 == other.p1 and self.p2 == other.p2) or (self.p1 == other.p2 and self.p2 == other.p1)):
			return 0
		else:
			return -1

	def __hash__(self):
		return (hash(self.p1[0]) ^ hash(self.p1[1]) ^ hash(self.p2[0]) ^ hash(self.p2[1]))


class Orion:
	def __init__(self):
		self.TCPconns = collections.defaultdict(list) # all tcp different connections
		self.UDPconns = collections.defaultdict(list) # all udp different connections
		self.irc = collections.defaultdict(list) # all irc servers, chans and nicknames
		self.gets = [ ] # vector which contains all the gets
		self.posts = [ ] #vector which contains all the posts
		self.dns_requests = [ ] # to have only unique dns requests
		self.IRC_PATTERNS = [
			"USER",
			"USERHOST",
			"PASS",
			"NICK",
			"JOIN",
			"MODE",
			"MSG",
			"PRIVMSG",
			"PUBMSG",
			"TOPIC",
			"TOPICINFO",
			"CURRENTTOPIC",
			"identify"
		]
		
		self.pcapFile = " "
		self.directory = " "
		self.tcp_flag = False
		self.udp_flag = False
		self.irc_flag = False
		self.verbose = False
		self.get = False
		self.post = False
	
 	def populate( self , name ):
		h = open( name, "rb" )
		pcap = dpkt.pcap.Reader(h)
		print "sucaaa\n"
		try:
			for ts, buf in pcap:
				try:
					eth = dpkt.ethernet.Ethernet(buf) #add support to 802.11
					ip = eth.data
					if ip.p == dpkt.ip.IP_PROTO_TCP:
						tcp = ip.data
						src = ( ip.src, tcp.sport )
						dst = ( ip.dst, tcp.dport )
						cur_con = Connection( src, dst )					
						self.TCPconns[cur_con].append(ip)
						
					elif ip.p == dpkt.ip.IP_PROTO_UDP:
						udp = ip.data
						src = ( ip.src, udp.sport )
						dst = ( ip.dst, udp.dport )
						cur_con = Connection( src, dst )		
						self.UDPconns[cur_con].append(ip)
						self.TimeUDPconns[cur_con].append(ts)
				except:
					pass
		except:
			pass
		h.close()
		return True
	
	def check_http_request(self, tcpdata):
		try:
			dpkt.http.Request(tcpdata)
			return True
		except dpkt.dpkt.UnpackError:
			return False
			
	def check_http_response(self, tcpdata):
		try:
			dpkt.http.Response(tcpdata)
			return True
		except dpkt.dpkt.UnpackError:
			return False
			
	def check_dns(self, udpdata):
		try:
			dpkt.dns.DNS(udpdata)
			return True
		except:
			return False
	
	def parse( self ):
		tcp_pkt_tot = 0
		tcp_con = 0
		get_tot = 0
		post_tot = 0
		irc_tot = 0
		dst = " "
		
		if self.verbose and self.tcp_flag:
			print ":: TCP Connections: "
		if self.tcp_flag:
			for key, value in self.TCPconns.iteritems( ):
				tcp_con += 1    
				if self.verbose:
					print "\n%d) %s:%d <--> %s:%d" % (tcp_con, socket.inet_ntoa(key.p1[0]), key.p1[1], socket.inet_ntoa(key.p2[0]), key.p2[1])
				pkt_num = len(self.TCPconns[key])
				if self.verbose:
					print "o Number of packets: %d" % pkt_num
				
				tcp_pkt_tot += pkt_num
				size = 0
				
				for ipPkt in range(0,len(self.TCPconns[key])):
					ip = self.TCPconns[key][ipPkt]
					tcp = ip.data
					if len(tcp.data) > 0:
						#Parsing generic get & posts
						if self.check_http_request(tcp.data):
							if tcp.data[:3] == "GET":
								get_tot += 1
								addr = self.get_urlName(tcp.data, "GET")
								self.gets.append(addr)
								continue
							elif tcp.data[:4] == "POST":
								post_tot += 1
								addr = self.get_urlName(tcp.data, "POST")
								self.posts.append(addr)
								continue
						# How to find Servers, Nicknames and chans
						# Solution for servers & nicknames: USER -> user <username> <hostname> <servername> <realname>
						# Solution for chans: JOIN #chan1,chan2,chan3 etc
						if self.irc_flag:
							for pattern in self.IRC_PATTERNS:
								if re.search("USER", tcp.data):
									irc_info = [ ]
									info = tcp.data								
									irc_info = info.split()
								chan_info = tcp.data
								if chan_info.startswith("ns"):
									raw_login = [ ]
									raw_login = chan_info.split()
									password = raw_login[2]
								if chan_info.startswith("JOIN"):
									chan_raw = [ ]
									chan_raw = chan_info.split(',')
									for chan in chan_raw:
										if chan == "x" or chan == "x\r\n":
											continue
										irc_key = "Server: %s ->  %s  %s" % (irc_info[5], irc_info[1], password)
										value = chan
										if value in self.irc[irc_key]:
											continue
										self.irc[irc_key].append(value)
								if re.search(pattern, tcp.data) and tcp.dport != 1863:
									if self.verbose:
										print "o IRC: %s" % tcp.data
									irc_tot += 1
									continue

		if self.verbose and self.udp_flag:		
			print ":: UDP Connections: "
		if self.udp_flag:
			udp_con = 0
			udp_pkt_tot = 0
			for key, value in self.UDPconns.iteritems():
				udp_con += 1
				pkt_num = len(self.UDPconns[key])
				if self.verbose:
					print "\n%d): %s:%d <--> %s:%d" % (udp_con, socket.inet_ntoa(key.p1[0]), key.p1[1], socket.inet_ntoa(key.p2[0]), key.p2[1])
					print "o Number of packets: %d" % (len(self.UDPconns[key]))
				udp_pkt_tot += pkt_num
				if self.verbose:
					for ipPkt in range(0,len(self.UDPconns[key])):
						ip = self.UDPconns[key][ipPkt]
						udp = ip.data
						pkt = udp.data
						if len(pkt) > 0:
							if self.check_dns(pkt):
								dns = dpkt.dns.DNS(pkt)
								try:
									name = dns.qd[0].name
								except:
									pass			
								if name not in self.dns_requests:
									self.dns_requests.append(name)
									print "Request to %s " % name
									pass
				
		if self.tcp_flag:
			self.TCPpkts = tcp_pkt_tot
			print "\n:: TCP connections: %d -> Total packets: %d" % (tcp_con, tcp_pkt_tot)
			if self.get:
				print "o Number of GET:  %d" % get_tot
				if get_tot > 0:
					self.list_get( )
			if self.post:
				print "o Number of POST: %d" % post_tot
				if post_tot > 0:
					self.list_post( )
			
		if self.irc_flag:
			print ":: IRC packets: %d" % irc_tot
			for key, value in self.irc.iteritems( ):
				print "o %s" % key
				for info in self.irc[key]:
					if info.startswith("JOIN"):	
						print " %s" % info[5:]
					else:
						print " %s" % info
	
		
		if self.udp_flag:
			self.UDPpkts = udp_pkt_tot
			print "\n:: UDP connections: %d -> Total packets: %d" % (udp_con, udp_pkt_tot)
			
	def list_get( self ):
		for g in self.gets:
			print " %s" % g
	
	def list_post( self ):
		for p in self.posts:
			print " %s" % p

	def get_urlName( self, data, method ):
		http = dpkt.http.Request(data)
		stuff = data.split( '\r\n' )
		b = data.find( 'Host' )
		e = data.find( '\r\n', b )
		dst = data[b+5:e]
		if method == "GET":
			name = string.lstrip( http.uri, "GET")
		elif method == "POST":
			name = string.lstrip( http.uri, "POST")
		else:
			return
		return dst + name

	def check_dns(self, udpdata):
		try:
			dpkt.dns.DNS(udpdata)
			return True
		except:
			return False

	def mkdir(self, directory):
		if not os.path.exists(directory):
			try:
				os.mkdir(directory)
			except:
				return False
			else:
				return True
		else:
			print "Error: directory already exists"

	def download(self, url, where):
		try:
			handle = urllib2.urlopen(url)
			tmp = []
			tmp = url.split('/')	
			name = where + '/' + tmp[len(tmp)-1]
			output = open(name,'wb')
			output.write(handle.read())
			output.close()
			print "orion$ %s has been successfully downloaded in %s" % (tmp[len(tmp)-1], where)
			return True
		except:
			return False

	def help(self):
		print '\n ** Help for orion\'s syntax **\n'
		print ' o help -> print this help message'
		print ' o load file.pcap -> populate the data structure with the info extracted by the pcap file'
		print ' o show tcp/irc/udp/http/get/post -> show information about tcp/irc/udp/http/get/post sessions'
		print ' o verbose irc -> show payloads of the captured irc packets'
		print ' o list tcp/udp -> list the tcp/udp connections'
		print ' o mkdir absolute path -> create a dir (handy if it is used before the command download or dump)'
		print ' o download url -> try to download a file from the net (http:// in url is required)'
		print ' o dump exe/pdf -> try to dump from the pcap file exe or pdf files'
		print ' o exit/quit -> exit from orion\n'

	def work(self, cmd):
		if cmd.startswith("load"):
			orion.pcapFile = cmd[5:]
			print "orion is loading %s..." % orion.pcapFile
			orion.populate(orion.pcapFile)
		elif cmd == "show irc":
			orion.tcp_flag = True
			orion.irc_flag = True
			orion.verbose = False
			orion.udp_flag = False
			orion.get = False
			orion.post = False
			orion.parse( )
		elif cmd == "show tcp":
			orion.tcp_flag = True
			orion.irc_flag = False
			orion.verbose = False
			orion.udp_flag = False
			orion.get = False
			orion.post = False
			orion.parse( )
		elif cmd == "show udp":
			orion.udp_flag = True
			orion.tcp_flag = False
			orion.irc_flag = False
			orion.verbose = False
			orion.get = False
			orion.post = False		
			orion.parse( )
		elif cmd == "show http":
			orion.udp_flag = False
			orion.tcp_flag = True
			orion.irc_flag = False
			orion.verbose = False
			orion.get = True
			orion.post = True
			orion.parse( )
		elif cmd == "show get":
			orion.udp_flag = False
			orion.tcp_flag = True
			orion.irc_flag = False
			orion.verbose = False
			orion.get = True
			orion.post = False
			orion.parse( )
		elif cmd == "show post":
			orion.udp_flag = False
			orion.tcp_flag = True
			orion.irc_flag = False
			orion.verbose = False
			orion.get = False
			orion.post = True
			orion.parse( )
		elif cmd == "verbose irc":
			orion.tcp_flag = True
			orion.irc_flag = True
			orion.verbose = True
			orion.udp_flag = False
			orion.get = False
			orion.post = False
			orion.parse( )
		elif cmd == "list udp":
			orion.tcp_flag = False
			orion.irc_flag = False
			orion.verbose = True
			orion.udp_flag = True
			orion.get = False
			orion.post = False
			orion.parse( )
		elif cmd == "list tcp":
			orion.tcp_flag = True
			orion.irc_flag = False
			orion.verbose = True
			orion.udp_flag = False
			orion.get = False
			orion.post = False
			orion.parse( )
		elif cmd.startswith("mkdir"):
			orion.directory = cmd[6:]
			if orion.mkdir(orion.directory):
				print "orion$ directory %s has been created" % orion.directory
			else:
				print "Error: directory not created"	
		elif cmd.startswith("download"):
			url = cmd[9:]
			if orion.directory == " ":
				orion.directory = os.getcwd()
				print "Downloading %s in %s..." % (url, orion.directory)
				if not orion.download(url, orion.directory):
					print "Error: file not downloaded"
			else:
				if not orion.download(url, orion.directory):
					print "Error: file not downloaded"
		elif cmd == "help":
			orion.help()
		elif cmd == "exit" or cmd == "quit":
			sys.exit()
		else:
			print "Error: command not found"
			orion.help()

#Begin
if __name__ == '__main__':
	print "\t\t** orion - Mariano 'emdel' Graziano - 5D4A LAB **\n"
	orion = Orion( )
	try:
		while(1):
			cmd = raw_input('orion$ ')
			orion.work(cmd)	
	except KeyboardInterrupt:
		print '\nExiting...'
      
