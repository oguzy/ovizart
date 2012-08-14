OVIZART =  Open VİZual Analsis foR network Traffic
==================================================

Installation
============

Ovizart application is a Django based web application. It can be either run on your machine by using the Django's
development server or by installing a web server and setting the wsgi type handler to handle the Python code.

Using Development Server
------------------------

The explanations will be covered according to a Debain based system.

* Clone the source code from Github

This required Git installation.

    $ sudo apt-get install git-core

After the installation is finished, git command is available for usage

    $ git clone https://github.com/oguzy/ovizart.git

* Install zc.buildout and some other Python bindings that are used at the application

python-dpkt is used to handle protocol based information. It is both used for getting TCP/UDP pached headers, payloads,
sized and application level data.

python-magic is used to get file MIME types.

python-pip is used during buildout process to get required third party Python bindings.

Mercurial is necessary to run "hg clone" command at the command line.

	$ sudo apt-get install python-zc.build mercurial python-pip python-dpkt python-magic

Like some third parth Python bindings it is required external programs also. They are tshark and tcpflow.

    $ sudo apt-get install tshark tcpflow

*tshark* is required for an alternative method to detect application layer protocols where bro fails
At some level, Bro is not able to detect missing handshaked application level protocols, though tshark does.

*tcpflow* is used to get reassembled TCP information whenever Bro's handler is not good enough. It is seen that tcpflow works
much better for SMTP traffic, for ex.

* Run the buildout command to initialize and install the requirements

This will download the required thir party python bindings, put the eggs in the directories.

	$ python bootstrap.py

This command may give errors, which means some directories are already created. So running the buildout will solve the issue.

	$ buildout2.7


If the command runs succesfully new directories should be seen at the ovizart directory.They are *bin*, *develop-eggs*,
*eggs*, *parts* and *requirements* directories. Except from *bin* directory, others keep the required third-party bindings that are
defined at the buildout.cfg file. *bin* directory is the one that will help us use Django commands like "runserver* or *shell*.

Ovizart application uses mongodb to keep data.

* Install mongodb server

It is a NoSQL server.

	$ sudo apt-get install mongodb-server

You may test the mongodb running by writing mongo to he command line
it you see an shell like below then you may continue to create the tables at the database

	$ mongo
	MongoDB shell version: 2.0.4
	connecting to: test

* To create tables requires using *django* command usage.

Assuming that the cloned directory name is ovizart, first enter the directory where *bin* directory is.

    $ cd ovizart

Then run the django command

    $ bin/django syncdb

If there is no error saying that there is no mongo db backend, then the Django API will start creating tables. It will ask
to create admin realted tables, say no to that.

If the table creation finishes successfully, a demo user is required to be defined. Running the user create script will
do it for you.

    $ cd ovizart
    $ python scripts/create_user.py

This will add a user with the below credentials:

    username: demo
    user email: demo@ovizart.foo.com
    password: ozyy4r12

* If you got backend errors like *django.core.exceptions.ImproperlyConfigured: 'django_mongodb_engine' isn't an
available database backend.* then install the django-mongodb backend manually.

Buildout should be handling them and there shouldn't be a requirement for installing them manually if you are not
planning to use development server.

	$ pip install hg+https://bitbucket.org/wkornewald/django-nonrel
	$ pip install hg+https://bitbucket.org/wkornewald/djangotoolbox
	$ pip install git+https://github.com/django-nonrel/mongodb-engine

* Django application requires some directories with writable permission. At the directory where settings.py is, three
directories require writable permission to let the server process create files inside them.

	$ chmod a+w uploads
	$ chmod a+w json_files
    $ chmod a+w csv_files

If these directories are not listed, then create them first.

* Bro-ids is required for protocol detection. Download and extract the source first

    $ wget http://www.bro-ids.org/downloads/release/bro-2.0.tar.gz
    $ tar xvzf bro-2.0.tar.gz
    $ cd bro-2.0

Compiling the Bro source requires some additional libraries installed.

The commands are tested under Kubuntu 12.04. At Debian Squeeze, swig2.0 should be removed from the command line.

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

* Bro is used both for protocol detection and TCP reassembly. To let Bro handle assemble the contents, a file should be
changed. If you installed Bro to /usr/local/bro/ then edit the file /usr/local/bro/share/bro/base/protocols/conn/contents.bro as below

Although it is used for IDS, Bro is used for TCP reassembly issues at this project.

	\#\# If this variable is set to ``T``, then all contents of all connections  
	\#\# will be  extracted.  
	const default_extract = T &redef;

* It is required two development server processes running.

    $ bin/django runserver
    $ bin/django runserver 127.0.0.1:8001

After this step the application is ready to be used. Open the browser and go to the address http://127.0.0.1:8001. By using
login credentials, you may upload raw traffic files, mainly pcap formatted files.

Current beta version supports HTTP, DNS and SMTP traffic analyzing. Use login part only for uploads. After upload, logout and check the
uploaded traffic details. The logins pages are not fixed yet.