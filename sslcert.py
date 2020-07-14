#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""SSL Grader"""
__author__ = "Kevin Amorin"
__copyright__ = "Copyright 2020"
__license__ = "GPL"
__version__ = "1.0.1"

import sys, os
from shodan import Shodan
from pprint import pprint, pformat
import pickle
from OpenSSL import crypto
from datetime import datetime
import certifi
import pem
import logging
import argparse
from prettytable import PrettyTable
import csv
import censys.certificates
import censys.ipv4

ROOT_STORE = None

def log(s, type="DEBUG"):
    """ log wrapper """
    levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
    logging.log(levels[type], s)


def extract_altname(server_crt):
    """ Helper: parse PEM formated certificate chain list for v3 extention alt-names

        :param server_crt: list of PEM certs in UTF-8 string format
        :type server_crt: list
    """
    x509cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_crt)
    san = ""
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            san = ext.__str__().replace("DNS", "").replace(":", "").split(", ")

    return san


def load_root_ca_list():
    """ load all certificates found in openssl cert.pem (via certifi.where())
        
        :return: returns X509store obj loaded with trusted Cert.  
        :rtype: X509store
    """
    store = None
    try:
        # Mac shipps with 175 root CA certs vs. 139 from pyOpenssl.  In my testing, the 175s vs. 139
        # didn't result in increase in validation count across 10k certs.  However your mileage may vary
        # reaplce apple-system-root.pem w/ certifi.where() to use openssl cert store
        with open("apple-system-root.pem", "rb") as f:
            certs = pem.parse(f.read())
            store = crypto.X509Store()
            for cert in certs:
                cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_text())
                store.add_cert(cacert)
                log(f"loading root CA store w/ {cacert.get_subject()} ")
    except EnvironmentError:  # parent of IOError, OSError *and* WindowsError where available
        log(f"No CA Store found at {certifi.where()}, can not validate\n\n", "ERROR")
        raise FileNotFoundError
    return store


class graderCert(object):
    """  store certs in a common format and grade their security on a 0-100 scale, 0 poor-100 strong
    """
    grade = 100
    issues = None

    def __init__(self, **kwargs):
        self.issues = []
        pprint(f"SETTING UP GRADER {kwargs.items()}")
        for key, value in kwargs.items():
            pprint(f"KEY={key} V={value}")
            setattr(self, key, value)

    def __repr__(self):
        return pformat(self.__dict__)

    def grade_cert(self):
        """ process cert attributes, add to list of issues and update grade
        """
        if self.sig_alg != "sha256WithRSAEncryption":
            self.issues.append(f"Signature algorithm weak {self.sig_alg}")
            self.grade -= 10

        # dhparams': {'bits': 4096,
        # ECDHE enable forward secrecy with modern web browsers

        if "RSA" not in self.cipher["name"] or  \
           "ADH" in self.cipher["name"] or  \
           "CBC" in self.cipher["name"] or  \
           "RC4" in self.cipher["name"] or  \
           "TLS-RSA" in self.cipher["name"]:
            self.issues.append(f"Bad cipher {self.cipher['name']}")
            # Cipher Block Chaining (CBC) ciphers were marked as weak (around March 2019)
            self.grade -= 10

        if self.pubkey["bits"] < 2048:
            self.issues.append(f"Bits {self.pubkey['bits']} <2048")
            self.grade -= 10

        if self.expired:
            self.issues.append(f"Expired Cert {self.expires}")
            self.grade -= 10

        if "SSLv3" in self.cipher["version"]:
            self.issues.append("SSLv3 supported")
            self.grade -= 10

        if "TLSv1" in self.cipher["version"]:
            self.issues.append("TLSv1 supported")
            self.grade -= 10

        if self.server_cert:
            self.verify_chain_of_trust()
        
        if not self.validation:
            self.issues.append("Failed Chain of Trust validation : " + self.validation_reason)
            self.grade -= 20
    
    def verify_chain_of_trust(self):
        """  openssl manual validation of chain.  store validation result in self.validation 
            
            :param server_cert: server cert in PEM UTF-8 string format
            :type server_cert: str
            :param trusted_chain: list of intermediate certs in PEM UTF-8 string format
            :type trusted_chain: list of str
        """
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, self.server_cert)
        log(f"loaded server cert: {certificate.get_subject().CN}", "INFO")

        if self.trust_chain:
            for trusted_cert_pem in self.trust_chain:
                trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
                log(f"added intermediate cert {trusted_cert.get_subject()}")
                ROOT_STORE.add_cert(trusted_cert)

        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(ROOT_STORE, certificate)
        # Rasies exception if certificate is not valid
        try:
            store_ctx.verify_certificate()
        except Exception as e:
            log(f"Validation Failed: {e.args[0][2]}")
            self.validation = False
            self.validation_reason = e.args[0][2]
            return

        log("Validation Successful")
        self.validation = True
        self.validation_reason = None


class certSearch(object):
    """ facade search obj
    """
    
    def __init__(self, search_engine, use_cache, result_limit, api_id, api_secret=None):
        self.use_cache=use_cache
        self.search_engine = search_engine
        if search_engine == "SHODAN":
            self.searchAPI = shodanSearch(result_limit, api_id)
        else:
            self.searchAPI = censysSearch(result_limit, api_id, api_secret)

    def load_raw_results(self):
        '''  load search results from self.raw_results into common format dict self.results '''
        certs = []
        for result in self.searchAPI.raw_results:
            # load results and convert it to a dict we can grade
            certs.append(self.searchAPI.load(result))
        self.searchAPI.results = certs

    def search(self, domain):
        ''' load raw cache or  '''
        self.domain=domain
        self.raw_results=[]
        #load cache of raw search results
        if self.use_cache:
            self.load_cache(domain)        
        if not self.raw_results:
            self.searchAPI.search(domain)
            self.save_cache(domain)
        self.load_raw_results()

    def get_results(self):
        return self.searchAPI.results

    def get_raw_results(self):
        return self.searchAPI.raw_results
    
    def load_cache(self,filename=None):
        ''' load raw search results into raw_results from pickled file'''
        try:
            log(f"-Reading cached data from {filename}.pkl\n", "INFO")
            with open(f"{filename}-{self.search_engine}.pkl", "rb") as f:
                self.searchAPI.raw_results = pickle.load(f)
        except IOError:
            log(f"-Cache file not accessible for {filename}", "INFO")

    def save_cache(self, filename=None):
        pickle.dump(self.searchAPI.raw_results, open(f"{filename}-{self.search_engine}.pkl", "wb"))
  

class censysSearch(object):
    """ censys obj """
    RESULT_FIELDS = ['443','11211','143','1433','161','25','3306','3389','465','5432','5672','631','6379','6443','8883','ip','993','995']
    SEARCH_FIELDS = [ 
                    '443.https.tls.certificate.parsed.names',
                    '11211.memcached.banner.tls.certificate.parsed.names',
                    '143.imap.starttls.tls.certificate.parsed.names',
                    '1433.mssql.banner.tls.certificate.parsed.names',
                    '161.snmp.banner.tls.certificate.parsed.names',
                    '1883.mqtt.banner.tls.certificate.parsed.names',
                    '25.smtp.starttls.tls.certificate.parsed.names',
                    '3306.mysql.banner.tls.certificate.parsed.names',
                    '3389.rdp.banner.tls.certificate.parsed.names',
                    '465.smtp.tls.tls.certificate.parsed.names',
                    '5432.postgres.banner.tls.certificate.parsed.names',
                    '5672.amqp.banner.tls.certificate.parsed.names',
                    '631.ipp.banner.tls.certificate.parsed.names',
                    '6379.redis.banner.tls.certificate.parsed.names',
                    '6443.kubernetes.banner.tls.certificate.parsed.names',
                    '8883.mqtt.banner.tls.certificate.parsed.names',
                    '9200.elasticsearch.banner.tls.certificate.parsed.names',
                    '993.imaps.tls.tls.certificate.parsed.names',
                    '995.pop3s.tls.tls.certificate.parsed.names',
                    ]

    def __init__(self, result_limit, api_id, api_secret):
        # parse SEARCHFIELDs and create a dict pointing to TLS 
        self.search_key={}
        for item in self.SEARCH_FIELDS:
            terms=item.split('.')
            self.search_key[terms[0]]=terms[:-3]
        self.result_limit = result_limit
        self.CENSYS_API_ID,self.CENSYS_API_SECRET=(None,None)
        if api_id:
            self.CENSYS_API_ID = api_id
            self.CENSYS_API_SECRET = api_secret
        elif os.getenv("CENSYS_API_ID", None) and os.getenv("CENSYS_API_SECRET", None): 
            self.CENSYS_API_ID = os.environ["CENSYS_API_ID"]
            self.CENSYS_API_SECRET = os.environ["CENSYS_API_SECRET"]

    def load(self,result):
        certinfo = {}
        tls = {}

        for port in result:
            if self.search_key.get(port,None):
                print(f"processing : port{port} {self.search_key[port]}")
                tls=result
                for path in self.search_key[port]:
                    # iterate down dictionary until TLS certificate node reached
                    if tls.get(path,None):
                        tls=tls[path]
                    else:
                        print(f"ERROR in DATA!! {self.search_key[port]}")

                if not tls.get('certificate',None):
                    print(f"port {port} missing TLS cert")
                    break
        
                #pprint(result[port])
                certinfo = {
                    'source' : "Censys",
                    'ip' : result['ip'],
                    'hostname' : result['ip'],
                    'altnames' : tls['certificate']['parsed']['names'],
                    'server_cert' : None,
                    'trust_chain' : None,
                    'expires' : tls['certificate']['parsed']['validity']['end'],
                    'version' : tls['version'],
                    'cipher' :  {'name' : tls['cipher_suite']['name'],
                                'version' : tls['version'],
                                },
                    'pubkey' :  {'bits' : tls['certificate']['parsed']['subject_key_info']['rsa_public_key']['length'],
                                    'type' : tls['certificate']['parsed']['subject_key_info']['key_algorithm']['name'],
                                },
                    'sig_alg' :  tls['certificate']['parsed']['signature_algorithm']['name'],
                    'subject' :  (tls['certificate']['parsed']['subject']).get('common_name',None),
                    'issued' :  tls['certificate']['parsed']['validity']['start'],
                    'validation' : tls['validation']['browser_trusted'],
                }
                if not tls['validation']['browser_trusted']:
                    certinfo['validation_reason']="validation error" 
                else:
                    certinfo['validation_reason']=""
                    
                try:
                    certinfo['dhparams']=result['443']['https']['dhe']['dh_params']['prime']['length']
                except KeyError:
                    certinfo['dhparams']=None
                try:
                    certinfo['heartbleed_enabled']=result['443']['https']['heartbeat_enabled']
                except KeyError:
                    certinfo['heartbleed_enabled']=None
                
                if (datetime.strptime(tls['certificate']['parsed']['validity']['end'], "%Y-%m-%dT%H:%M:%SZ") < datetime.today()):
                    certinfo['expired']=True
                else:
                    certinfo['expired']=False

        #pprint(certinfo)
        return certinfo

    def search(self, domain):
        """  call Shodan API and save result list to self.raw_results
        """
        query = ' '.join([ '{0}:"{1}"'.format(x, domain) for x in self.SEARCH_FIELDS ])
        log(f"**Querying Censys with search query {query}\n", "INFO")

        censys_cert= censys.ipv4.CensysIPv4(api_id=self.CENSYS_API_ID,api_secret=self.CENSYS_API_SECRET)
        try:
            api = censys_cert.search(query, self.RESULT_FIELDS, flatten=False)
            self.raw_results = list(api)
        except censys.base.CensysUnauthorizedException:
            sys.stderr.write('[+] Censys account details wrong. \n')
            exit(1)
        except censys.base.CensysRateLimitExceededException:
            sys.stderr.write('[+] Limit exceeded.')
            exit(1)
        except censys.base.CensysException as e:
            # catch the Censys Base exception, example "only 1000 first results are available"
            sys.stderr.write('[-] Exception?, ' + repr(e))
            exit(1) 

    def get_results(self):
        return self.results

    def get_raw_results(self):
        return self.raw_results


class shodanSearch(object):
    """ shodan search api
    """
    def __init__(self, result_limit, api_key):
        self.result_limit = result_limit
        self.SHODAN_API = None
        if api_key:
            self.SHODAN_API = api_key
        elif os.getenv("SHODAN_API", None):
            self.SHODAN_API = os.environ["SHODAN_API"]

    def get_results(self):
        return self.results

    def get_raw_results(self):
        return self.raw_results

    def search(self, domain):
        """  call Shodan API and save result list to self.raw_results
        """
        api = Shodan(self.SHODAN_API)
        query = "ssl.cert.subject.cn:" + domain
        log(f"**Querying Shodan with Search query {query}\n", "INFO")
        self.raw_results=list(api.search_cursor(query))
        
    def load(self, result):
        """ take shodan result dict and convert it to a dict for use in grading
        """
        certinfo = {
            "source": "Shodan",
            "ip": result["ip_str"],
            "hostname": result["hostnames"],
            "isp": result["isp"],
            "subject": result["ssl"]["cert"]["subject"]["CN"],
            "expired": result["ssl"]["cert"]["expired"],
            "expires": result["ssl"]["cert"]["expires"],
            "pubkey": result["ssl"]["cert"]["pubkey"],
            "sig_alg": result["ssl"]["cert"]["sig_alg"],
            "cipher": result["ssl"]["cipher"],
            "version": result["ssl"]["versions"],
            "dhparams": result["ssl"].get("dhparams", {"bits": float("inf"), "fingerprint": ""}),
            "issued": datetime.strptime(result["ssl"]["cert"]["issued"], "%Y%m%d%H%M%SZ"),
            "altnames": extract_altname(result["ssl"]["chain"][0]),
        }
        certinfo["server_cert"] = result["ssl"]["chain"][0]
        certinfo["trust_chain"] = None
        if len(result["ssl"]["chain"]) > 1:
            certinfo["trust_chain"] = result["ssl"]["chain"][1:]

        return certinfo


def print_report(certs):
    # print report
    table = PrettyTable()
    table.field_names = ["Source","Hostname", "Subject", "AltNames", "Grade", "Issues"]
    table._max_width = {"Source" : 2, "Hostname": 30, "Subject": 30, "AltNames": 30, "Grade": 5, "Issues": 50}
    for cert in certs:
        table.add_row([cert.source[0], cert.hostname, cert.subject, 
                       ", ".join(cert.altnames) + "\n\n", cert.grade, ", ".join(cert.issues) + "\n\n"])
    table.sortby = "Grade"
    print(table)

def csv_output(domain, certs):
     # optional CSV output
    if csv_output:
        with open(domain + ".csv", "w", newline="") as csvfile:
            certwriter = csv.writer(csvfile, quotechar='"')
            certwriter.writerow(["Hostname", "Subject", "AltNames", "Grade", "Issues"])
            for cert in certs:
                certwriter.writerow([", ".join(cert.hostname), cert.subject, 
                                     ", ".join(cert.altnames), cert.grade, ", ".join(cert.issues)])


if __name__ == "__main__":
    """  parse args, set global API Keys and execute search function
    """
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="ssl-cert.py", description="ssl-cert grader")
    parser.add_argument("domain", help="subdomain to search for certificates")
    parser.add_argument("-s", required=False, dest="api_key_shodan", help="Shodan API key")
    parser.add_argument("--censys_id", required=False, dest="api_key_censys_id", help="Censys API ID")
    parser.add_argument("--censys_secret", required=False, dest="api_key_censys_secret", help="Censys API Secret")
    parser.add_argument("-o", required=False, dest="csv_output", action="store_true", default=False, help="output report to a CSV file")
    parser.add_argument("-l", required=False, dest="result_limit", type=int, default=100, action="store", help="limit result set to save on API credits")
    parser.add_argument("-u", required=False, dest="use_cache", action="store_true", default=False, help="used cache to generate report")
    args = parser.parse_args()

    log(args, "INFO")
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")

    if args.domain:
        domain = args.domain

    # load root store
    ROOT_STORE = load_root_ca_list()

    certs = []

    search_list = [certSearch("SHODAN", args.use_cache, args.result_limit, args.api_key_shodan),
                   certSearch("CENSYS", args.use_cache, args.result_limit, args.api_key_censys_id, args.api_key_censys_secret)]
    
    for cert_search in search_list:
        cert_search.search(domain)

        for certinfo in cert_search.get_results():
            #pprint(certinfo)
            if not certinfo.keys():
                print("ERROR!!!!")
                continue
            cert = graderCert(**certinfo)
            cert.grade_cert()
            certs.append(cert)

print_report(certs)
if args.csv_output:
    csv_output(domain, certs)