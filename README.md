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

If you want to run the latest version of the code, you can install from git:

    $ python3 -m pip install -U git+git://github.com/kamorin/ssl-grader.git

    $ pip3 install -r test-requirements.txt


example: python3 ssl-cert.py wpi.edu

    $ python3 ssl-cert.py [domain to search]  [SHDOAN_API]


License
-------

ssl-grader is licensed under the terms of the MIT License (see the file
LICENSE).

