#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""SSL Grader"""
__author__      = "Kevin Amorin"
__copyright__   = "Copyright 2020"
__license__ = "GPL"
__version__ = "1.0.1"

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

# add to different obj?
ROOT_STORE=None

def log(s,type='INFO'):
    '''  TODO: update to handle types better
    '''
    if isinstance(s,str):
        lines=pformat(s.splitlines()).splitlines()
    else:
        lines=pformat(s).splitlines()
    for line in lines:
        if type in 'DEBUG':
            logging.debug(line)
            logging.debug("\n")
        elif type in 'INFO':
            logging.info(line)
        elif type in 'WARN':
            logging.warn(line)

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
                log(f"loading root CA store w/ {cacert.get_subject()} ",'DEBUG')
    except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
        print(f'No CA Store found at {certifi.where()}, can not validate\n\n')
        raise FileNotFoundError
    return store


class gradedCert(object):
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
            self.issues.append(f"WARNING signature algorith weak {self.sig_alg}")
            self.grade-=10
            
        # dhparams': {'bits': 4096,
        # ECDHE enable forward secrecy with modern web browsers
        
        if 'RSA' not in self.cipher['name']   \
                or 'ADH' in self.cipher['name']  \
                or 'CBC' in self.cipher['name']  \
                or 'RC4' in self.cipher['name']  \
                or 'TLS-RSA' in self.cipher['name']:
            self.issues.append(f"WARNING bad cipher {self.cipher}")
            self.issues.append('Since Cipher Block Chaining (CBC) ciphers were marked as weak (around March 2019) many, many sites now show a bunch of weak ciphers enabled and some are even exploitable via Zombie Poodle and Goldendoodle')   
            self.grade-=10

        if self.pubkey['bits'] < 2048:
            self.issues.append(f"WARNING bits={self.pubkey['bits']}")
            self.grade-=10
            
        if self.expired:
            self.issues.append(f"WARNING EXPIRED CERT {self.expires}")
            self.grade-=10
            
        if 'SSLv3' in self.cipher['version']:
            self.issues.append("WARNING SSLv3 SUPPORTED")
            self.grade-=10

        if 'TLSv1' in self.cipher['version']:
            self.issues.append("WARNING TLSv1 SUPPORTED")
            self.grade-=10


    def verify_chain_of_trust(self):
        '''  openssl manual validation of chain 
            
            :param cert_pem: server cert in PEM UTF-8 string format
            :type cert_pem: str
            :param trusted_cert_pem: list of intermediate certs in PEM UTF-8 string format
            :type trusted_cert_pem: list of str
            :return: return true if chain is verified
            :rtype: bool
        '''
        log(f"\n\n\nVERIFYING CHAIN OF TRUST ")

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, self.server_cert)
        log(f"loaded server certification {certificate.get_subject()}",'DEBUG')
        
        if self.trust_chain:
            for trusted_cert_pem in self.trust_chain:
                trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
                log(f"added intermediate cert {trusted_cert.get_subject()} \n",'DEBUG')
                ROOT_STORE.add_cert(trusted_cert)

        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(ROOT_STORE, certificate)
        # Returns None if certificate can be validated
        result=None
        try:
            result = store_ctx.verify_certificate()
        except Exception as e:
            print('exception occurred, value:', e)
            result=False

        if result is None:
            log("Validated",'INFO')
            return True
        else:
            return False


def search(SHODAN_API, query, TESTING_LOCAL=False):
    '''  call Shodan API and process results
    '''
    api = Shodan(SHODAN_API)
    if TESTING_LOCAL:
        try:
            log(f"***LOCAL TESTING ENABLED**\nReading cached data from results.pkl\n",'INFO')
            with open("results.pkl","rb") as f:
                results=pickle.load(f)
        except IOError:
            log("**Cache file not accessible, regening file",'INFO')
            results=api.search(query)
            pickle.dump(results,open("results.pkl","wb"))
    else:
        log(f"**Querying Shodan with Search query {query}\n",'INFO')
        results=api.search(query)

    graded_certs=[]
    for service in results['matches']:
        certinfo = { 'ip' : service['ip_str'],
                    'hostname' : service['hostnames'],
                    'isp' : service['isp'],
                    'subject' : service['ssl']['cert']['subject']['CN'],
                    'expired' : service['ssl']['cert']['expired'],
                    'expires' : service['ssl']['cert']['expires'],
                    'pubkey'  : service['ssl']['cert']['pubkey'],
                    'sig_alg' : service['ssl']['cert']['sig_alg'],
                    'cipher'  : service['ssl']['cipher'],
                    'version' : service['ssl']['versions'],
                    'dhparams': service['ssl'].get('dhparams',{'bits':float('inf'),'fingerprint':''}),
                    'issued'  : datetime.strptime(service['ssl']['cert']['issued'], "%Y%m%d%H%M%SZ"),
                    'altnames': extract_altname(service['ssl']['chain'][0]),
                    }
        certinfo['server_cert']=service['ssl']['chain'][0]
        certinfo['trust_chain']=None
        if len(service['ssl']['chain'])>1:
            certinfo['trust_chain']=service['ssl']['chain'][1:]

        cert=gradedCert(**certinfo)
        # load cert chain

        cert.verify_chain_of_trust()
        
        sys.exit(1)
        pprint(service)

        # grade
        cert.grade_cert()
        print(f" \n\n\nthe cert is graded: {cert.grade} with issues: {cert.issues}")
        
        graded_certs.append(cert)
                
    #grade_ssl(cert_list)
    #pprint(cert_list)


if __name__ == "__main__":
    '''  parse args, set global API Keys and execute search function
    '''
    parser = argparse.ArgumentParser(prog='ssl-cert.py',description='ssl-cert grader')
    parser.add_argument('--domain', required=False)
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(message)s')

    if os.getenv('SHODAN_API', None):
        SHODAN_API=os.environ['SHODAN_API']
    else:
        print("Set SHODAN_API ENV")
        sys.exit(1)

    # load root store    
    ROOT_STORE=load_root_ca_list()

    domain="wpi.edu"
    if args.domain:
        domain=args.domain
    query="ssl.cert.subject.cn:"+domain
    TESTING_LOCAL=True

    search(SHODAN_API, query, TESTING_LOCAL)
