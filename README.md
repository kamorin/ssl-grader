ssl-grader:  SSL certs collector and grader
=======================================

What is sslgrader?
-------------------

This program will do the following:
- query shodan for all certificates within a specific subdomain 
- query censys for all scanned certificates (non ctlogs)
- parse the results
- identify security issues with the certificate and/or the SSL server support on the server hosting the cert
- print table of certs order from worst to best

Requirements
------------
You need Python 3.5 or later.  You can have multiple Python versions (2.x and 3.x) installed on the same system without problems.

In Ubuntu, Mint and Debian you can install Python 3 like this:

    $ sudo apt-get install python3 python3-pip

For other Linux flavors, macOS and Windows, packages are available at

  https://www.python.org/getit/


Quick start
-----------

If you want to run the latest version of the code, you can install from github:

    $ curl -L https://github.com/kamorin/ssl-grader/archive/master.zip -o ssl-grader.zip
    $ unzip ssl-grader.zip -d ssl-grader
    $ cd ssl-grader
    $ pip3 install -r requirements.txt

usage: 

    $ sslcert.py [-h] [-s API_KEY_SHODAN] [-c API_KEY_CENSYS] [-o CSV_OUTPUT] [-l RESULT_LIMIT] [-u] domain

example search all certs in the subdomain ccis.neu.edu

    $ python3 sslcert.py -a XXXYYYSHODANAPIKEYZZZZZ ccis.neu.edu 

example:  search all certs in the domain wpi.edu and output to a CSV file

    $ python3 sslcert.py -a XXXYYYSHODANAPIKEYZZZZZ -o myfile.csv  wpi.edu 

example:  search all certs in the domain wpi.edu and set result limit to 1000, default is all results

    $ python3 sslcert.py -l 1000 -a XXXYYYSHODANAPIKEYZZZZZ  wpi.edu 


example:  search all certs in the domain bc.edu from Censys.  The Censys API should contain the Censys API ID and Secrete separated by a :

    $ python3 sslcert.py -c CENSYSID:CENSYSSECRETKEY  bc.edu

example:  search all certs in the domain bc.edu from Censys.  -u saves results to local cache.  Second call to ssl-cert uses local file bc.edu-CENSYS.pkl as cache and does not call the CENSYS API.

    $ python3 sslcert.py -u -c CENSYSID:CENSYSSECRETKEY  bc.edu      (saves results)
    $ python3 sslcert.py -u -c CENSYSID:CENSYSSECRETKEY  bc.edu      (uses local cached results)

License
-------

sslgrader is licensed under the terms of the MIT License (see the file
LICENSE).

