#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""SSL Grader"""
__author__      = "Kevin Amorin"
__copyright__   = "Copyright 2020"
__license__     = "GPL"
__version__     = "1.0.1"

import sys,os
from shodan import Shodan
from pprint import pprint,pformat
import pickle
from OpenSSL import crypto
from datetime import datetime
import certifi
import pem
import logging
import argparse
from beautifultable import BeautifulTable
import csv

ROOT_STORE=None

def log(s,type='DEBUG'):
    """ log wrapper """
    levels = {'DEBUG':10,
              'INFO':20,
              'WARNING':30,
              'ERROR':40,
              'CRITICAL':50 }
    logging.log(levels[type],s)

def extract_altname(server_crt):
    ''' Helper: parse PEM formated certificate chain list for v3 extention alt-names

        :param server_crt: list of PEM certs in UTF-8 string format
        :type server_crt: list
    '''
    x509cert=crypto.load_certificate(crypto.FILETYPE_PEM, server_crt)
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__().replace('DNS', '').replace(':', '').split(', ')
    
    return san

def load_root_ca_list():
    ''' load all certificates found in openssl cert.pem (via certifi.where())
        
        :return: returns X509store obj loaded with trusted Cert.  
        :rtype: X509store
    '''
    store = None
    try:
        with open(certifi.where(), 'rb') as f:
            certs=pem.parse(f.read())
            store = crypto.X509Store()
            for cert in certs:
                cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_text())
                store.add_cert(cacert)
                log(f"loading root CA store w/ {cacert.get_subject()} ")
    except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
        log(f'No CA Store found at {certifi.where()}, can not validate\n\n','ERROR')
        raise FileNotFoundError
    return store

class graderCert(object):
    '''  
    '''
    grade=100
    issues=None

    def __init__(self, **kwargs):
        self.issues=[]
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __repr__(self):
        return pformat(self.__dict__)

    def grade_cert(self):
        ''' process cert attributes, add to list of issues and update grade
        '''
        if self.sig_alg != 'sha256WithRSAEncryption':
            self.issues.append(f"Signature algorithm weak {self.sig_alg}")
            self.grade-=10
            
        # dhparams': {'bits': 4096,
        # ECDHE enable forward secrecy with modern web browsers
        
        if 'RSA' not in self.cipher['name']   \
                or 'ADH' in self.cipher['name']  \
                or 'CBC' in self.cipher['name']  \
                or 'RC4' in self.cipher['name']  \
                or 'TLS-RSA' in self.cipher['name']:
            self.issues.append(f"Bad cipher {self.cipher['name']}")
            #self.issues.append('Since Cipher Block Chaining (CBC) ciphers were marked as weak (around March 2019) many, many sites now show a bunch of weak ciphers enabled and some are even exploitable via Zombie Poodle and Goldendoodle')   
            self.grade-=10

        if self.pubkey['bits'] < 2048:
            self.issues.append(f"Bits {self.pubkey['bits']} <2048")
            self.grade-=10
            
        if self.expired:
            self.issues.append(f"Expired Cert {self.expires}")
            self.grade-=10
            
        if 'SSLv3' in self.cipher['version']:
            self.issues.append("SSLv3 supported")
            self.grade-=10

        if 'TLSv1' in self.cipher['version']:
            self.issues.append("TLSv1 supported")
            self.grade-=10

        self.verify_chain_of_trust()
        if not self.validation:
            self.issues.append("Failed Chain of Trust validation : "+self.validation_reason)
            self.grade-=20


    def verify_chain_of_trust(self):
        '''  openssl manual validation of chain.  store validation result in self.validation 
            
            :param server_cert: server cert in PEM UTF-8 string format
            :type server_cert: str
            :param trusted_chain: list of intermediate certs in PEM UTF-8 string format
            :type trusted_chain: list of str
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, self.server_cert)
        log(f"loaded server cert: {certificate.get_subject().CN}",'INFO')
        
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
            self.validation=False
            self.validation_reason=e.args[0][2]
            return
            
        log("Validation Successful")
        self.validation=True
        self.validation_reason=None

class certSearch(object):
    ''' facade search obj
    '''
    def __init__(self, search_engine, api_key, result_limit):
        if search_engine == "SHODAN":
            self.searchAPI=shodanSearch(api_key,result_limit)
        else:
            self.searchAPI=censysSearch(api_key,result_limit)
    
    def load(self,result):
        self.searchAPI.load(result)
    
    def search(self,domain,load_cache):
        self.searchAPI.search(domain,load_cache)

    def get_results(self):
        return self.searchAPI.results


class censysSearch(object):
    ''' TODO: censys '''
    def __init___(self,api_key=None,result_limit=100):
        pass
    def load():
        pass
    def search():
        pass


class shodanSearch(object):
    '''
    '''
    def __init__(self, api_key=None, result_limit=100):
        self.result_limit=result_limit
        if api_key:
            self.SHODAN_API=api_key
        elif os.getenv('SHODAN_API', None):
            self.SHODAN_API=os.environ['SHODAN_API']
        else:
            log("SHODAN_API Key missing.  Pass as argument or set SHODAN_API env var",'ERROR')
            sys.exit(1)

    def get_results():
        return self.results

    def search(self, domain, use_cache=False):
        '''  call Shodan API and return results
        '''    
        if use_cache:
            try:
                log(f"-LOCAL REPORT GENERATION\n-NOT CALLING SHODAN\n-Reading cached data from {domain}.pkl\n",'INFO')
                with open(f"{domain}.pkl","rb") as f:
                    self.results=pickle.load(f)
                    return
            except IOError as e:
                log(f"-Cache file not accessible, regening file {e}",'INFO')
        
        api = Shodan(self.SHODAN_API)
        query="ssl.cert.subject.cn:"+domain
        log(f"**Querying Shodan with Search query {query}\n",'INFO')
        limit = self.result_limit
        counter = 0
        certs=[]
        for result in api.search_cursor(query):
            print(f"RESULT count={counter} \n")
            # html large result, del now and save space
            result.pop('html', None)
            
            #load shodan results and convert it to a dict we can grade
            certs.append(self.load(result))


            counter += 1
            if counter >= limit:
               break

        if use_cache:
            pickle.dump(certs,open(f"{domain}.pkl","wb"))

        self.results=certs


    def load(self, result):
        ''' load shodan results into a list of 
        '''
        certinfo = { 'ip' : result['ip_str'],
                    'hostname' : result['hostnames'],
                    'isp' : result['isp'],
                    'subject' : result['ssl']['cert']['subject']['CN'],
                    'expired' : result['ssl']['cert']['expired'],
                    'expires' : result['ssl']['cert']['expires'],
                    'pubkey'  : result['ssl']['cert']['pubkey'],
                    'sig_alg' : result['ssl']['cert']['sig_alg'],
                    'cipher'  : result['ssl']['cipher'],
                    'version' : result['ssl']['versions'],
                    'dhparams': result['ssl'].get('dhparams',{'bits':float('inf'),'fingerprint':''}),
                    'issued'  : datetime.strptime(result['ssl']['cert']['issued'], "%Y%m%d%H%M%SZ"),
                    'altnames': extract_altname(result['ssl']['chain'][0]),
                    }
        certinfo['server_cert']=result['ssl']['chain'][0]
        certinfo['trust_chain']=None
        if len(result['ssl']['chain'])>1:
            certinfo['trust_chain']=result['ssl']['chain'][1:]
        
        # # load dictionary into initializer 
        # cert=graderCert(**certinfo)
        # cert.grade_cert()

        return certinfo



if __name__ == "__main__":
    '''  parse args, set global API Keys and execute search function
    '''
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser(prog='ssl-cert.py',description='ssl-cert grader')
    parser.add_argument('domain', help="subdomain to search for certificates")
    parser.add_argument('-a', required=False, dest="api_key", help="Shodan API key")
    parser.add_argument('-c', required=False, dest="csv_output", action='store_true', default=False,  help="output report to a CSV file")
    parser.add_argument('-l', required=False, dest="result_limit", type=int, default=100, action='store',  help="limit result set to save on API credits")
    parser.add_argument('-u', required=False, dest="use_cache", action='store_true', default=False, help="used cache to generate report")
    args = parser.parse_args()
    
    pprint(args)
    csv_output=args.csv_output
    use_cache=args.use_cache
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(message)s')

    
    if args.domain:
        domain=args.domain

    # load root store    
    ROOT_STORE=load_root_ca_list()

    certs=[]
    mysearch = certSearch('SHODAN', args.api_key, args.result_limit)
    mysearch.search(domain, use_cache)
    pprint(mysearch.get_results())

    
    for certinfo in mysearch.get_results():
        cert=graderCert(**certinfo)
        cert.grade_cert()
        certs.append(cert)

    # print report
    table = BeautifulTable(max_width=140)
    table.column_headers = ["Subject", "AltNames","Grade", "Issues"]
    table.set_style(BeautifulTable.STYLE_MYSQL)
    for cert in certs:
        table.append_row([cert.subject,cert.altnames[:100],cert.grade,cert.issues])
    table.sort('Grade')
    print(table)
    
    # optional CSV output
    if csv_output:
        with open(domain+".csv", 'w', newline='') as csvfile:
            certwriter = csv.writer(csvfile)
            certwriter.writerow(["Subject", "Grade", "Issues"])
            for cert in certs:
                certwriter.writerow([cert.subject,cert.grade,cert.issues])

