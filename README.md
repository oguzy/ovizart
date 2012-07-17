Installation
============

* Install zc.buildout


At Ubuntu this is done via the command below

	$ sudo apt-get install python-zc.build, mercurial, python-pip, python-dpkt

* Run the buildout command to initialize and install the requirements

This will download the required thir party python bindings, put the eggs in the directories.

	$ cp buildout.cfg.org buildout.cfg
	$ python bootstrap.py
	$ buildout2.7

* install mongodb server

It is a NoSQL server.

	$ sudo apt-get install mongodb-server

You may test the mongodb running my writing mongo to he command line
it you see an shell like below then you may continue with bro installation

	$ mongo
	MongoDB shell version: 2.0.4
	connecting to: test

Requirements for Bro installation
---------------------------------

The commands are testet under Kubuntu 12.04. At Debian Squeeze, swig2.0 should be removed from the command line.

	$ sudo apt-get install libmagic-dev libgeoip-dev libpcap-dev libssl-dev libncurses5-dev g++ bison flex cmake swig2.0 make gcc g++ python-dev zlib1g-dev
	$ ./configure --enable-debug
	$ make
	$ sudo make install
	$ cd /usr/local/bro/bin
	$ sudo broctl
	$ install
	$ start
	$ stop
	$ check
	$ exit
	$ /usr/local/bro/bin/bro -C -r pcap_fille.name should be working


* Bro is used both for protocol detection and TCP reassembly. To let Bro handle assemble the contents, a file should be changed. If you installed Bro to /usr/local/bro/ then edit the file /usr/local/bro/share/bro/base/protocols/conn/contents.bro as below

Although it is used for IDS, Bro is used for TCP reassembly issues at this project.

	\#\# If this variable is set to ``T``, then all contents of all connections  
	\#\# will be  extracted.  
	const default_extract = T &redef;  

* tshark is required for an alternative method to detect application layer protocols where bro fails

At some level, Bro is not able to detect missing handshaked application level protocols, though tshark does.

	$ sudo apt-get install tshark  


Django related issues
---------------------

* make a directory named *uploads* where the setting.py file is.

upload directory is used to keep the uploded pcaps, and json\_files are for created json responses and save them as files.

	$ mkdir uploads  
	$ chmod a+w uploads  
	$ chmod a+w json_files  

* If you got backend errors like *django.core.exceptions.ImproperlyConfigured: 'django_mongodb_engine' isn't an available database backend.*
install the django-mongodb backend manually

Buildout should be handling them and there shouldn't be a requirement for installing them manlually if you are not planning to use development server.

	$ pip install hg+https://bitbucket.org/wkornewald/django-nonrel  
	$ pip install hg+https://bitbucket.org/wkornewald/djangotoolbox  
	$ pip install git+https://github.com/django-nonrel/mongodb-engine  


Django projects requires a table creation first.

	$ bin/django syncdb  


The project uses hachoir Python library, install them also

	$ sudo apt-get install python-hachoir-* (i should add this part to the buildout configuration also)  


* to handle smtp, it is required to install tcpflow. After checking the results of Bro and Tcpflow, for smtp, the created flows files seem more manageable.

Tcpflow seems better while handling SMTP files.


	$ sudo apt-get install tcpflow  


