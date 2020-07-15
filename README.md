ssl-grader:  SSL certs collector and grader
=======================================

What is ssl grader?
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

example:  search all certs in the domain acme.edu and output to a CSV file

    $ python3 sslcert.py -a XXXYYYSHODANAPIKEYZZZZZ -o myfile.csv  acme.edu 

example:  search all certs in the domain acme.edu and set result limit to 1000, default is all results

    $ python3 sslcert.py -l 1000 -a XXXYYYSHODANAPIKEYZZZZZ  acme.edu 


example:  search all certs in the domain bc.edu from Censys.  The Censys API should contain the Censys API ID and Secrete separated by a :

    $ python3 sslcert.py -c CENSYSID:CENSYSSECRETKEY  bc.edu

example:  search all certs in the domain bc.edu from Censys.  -u saves results to local cache.  Second call to ssl-cert uses local file bc.edu-CENSYS.pkl as cache and does not call the CENSYS API.

    $ python3 sslcert.py -u -c CENSYSID:CENSYSSECRETKEY  bc.edu      (saves results)
    $ python3 sslcert.py -u -c CENSYSID:CENSYSSECRETKEY  bc.edu      (uses local cached results)

example output

```
+--------+--------------------------------+-------------------------------+--------------------------------+-------+----------------------------------------------------+
| Source |            Hostname            |            Subject            |            AltNames            | Grade |                       Issues                       |
+--------+--------------------------------+-------------------------------+--------------------------------+-------+----------------------------------------------------+
|   S    |         blargh.acme.edu        |         blargh.acme.edu       |                                |   20  | Signature algorithm weak md5WithRSAEncryption, Bad |
|        |                                |                               |                                |       | cipher AES256-GCM-SHA384, Bits 1024 <2048, Expired |
|        |                                |                               |                                |       |    Cert 20110425123248Z, SSLv3 supported, TLSv1    |
|        |                                |                               |                                |       | supported, Failed Chain of Trust validation : self |
|        |                                |                               |                                |       |                 signed certificate                 |
|        |                                |                               |                                |       |                                                    |
|        |                                |                               |                                |       |                                                    |
|   S    |    babylon5.goddard.acme.edu   |    babylon5.goddard.acme.edu  |                                |   30  |  Signature algorithm weak sha1WithRSAEncryption,   |
|        |                                |                               |                                |       |   Bits 1024 <2048, Expired Cert 20130319155442Z,   |
|        |                                |                               |                                |       | SSLv3 supported, TLSv1 supported, Failed Chain of  |
|        |                                |                               |                                |       |     Trust validation : self signed certificate     |
|        |                                |                               |                                |       |                                                    |
|        |                                |                               |                                |       |                                                    |
|   S    |        fh013-cp.acme.edu       |     FH013-CP.admin.acme.edu   |     FH013-CP.admin.acme.edu    |   30  |  Signature algorithm weak sha1WithRSAEncryption,   |
|        |                                |                               |                                |       |   Bits 1024 <2048, Expired Cert 20191007185823Z,   |
|        |                                |                               |                                |       | SSLv3 supported, TLSv1 supported, Failed Chain of  |
|        |                                |                               |                                |       |   Trust validation : unable to get local issuer    |
|        |                                |                               |                                |       |                    certificate                     |
|        |                                |                               |                                |       |                                                    |
|        |                                |                               |                                |       |                                                    |
|   C    |         130.215.140.25         |    equature-01-ilo.acme.edu   |    equature-01-ilo.acme.edu,   |   40  |  Signature algorithm weak SHA1WithRSA, Bad cipher  |
|        |                                |                               |        equature-01-ilo         |       |  TLS_RSA_WITH_RC4_128_SHA, Bits 1024 <2048, TLSv1  |
|        |                                |                               |                                |       |   supported, Failed Chain of Trust validation :    |
|        |                                |                               |                                |       |                  validation error                  |
|
```


License
-------

sslgrader is licensed under the terms of the MIT License (see the file
LICENSE).

