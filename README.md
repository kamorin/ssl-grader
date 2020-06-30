ssl-grader:  SSL certs collector and grader
=======================================

What is ssl-grader?
-------------------

This program will do the following:
- query shodan for all certificates within a specific subdomain 
- parse the results
- identify security issues with the certificate and/or the SSL server support on the server hosting the cert
- print table of certs order from worst to best

Requirements
------------
You need Python 3.5 or later to run mypy.  You can have multiple Python versions (2.x and 3.x) installed on the same system without problems.

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

    $ python3 ssl-cert.py [-h] [-a API_KEY] [-c] [-l RESULT_LIMIT] [-u] domain

example search all certs in the subdomain ccis.neu.edu

    $ python3 ssl-cert.py ccis.neu.edu -a XXXYYYSHODANAPIKEYZZZZZ

example:  search all certs in the domain wpi.edu and output to a CSV file

    $ python3 ssl-cert.py wpi.edu -c -a XXXYYYSHODANAPIKEYZZZZZ

example:  search all certs in the domain wpi.edu and set result limit to 1000, default is 100

    $ python3 ssl-cert.py wpi.edu -l 1000 -a XXXYYYSHODANAPIKEYZZZZZ

License
-------

ssl-grader is licensed under the terms of the MIT License (see the file
LICENSE).

