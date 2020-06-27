import sys,os
from shodan import Shodan
from pprint import pprint
import pickle
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.general_name import DNSName

def extract_x509_info_via_crypto(chain):
    chain_info={}
    cert_obj = x509.load_pem_x509_certificate(str.encode(chain), default_backend())
    common_name = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    chain_info['cn']=common_name
    san = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_dns_names = san.value.get_values_for_type(DNSName)
    chain_info['altnames']=san_dns_names
    return chain_info

def extract_x509_info(chain):
    x509cert=crypto.load_certificate(crypto.FILETYPE_PEM, chain[0])
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__().replace('DNS', '').replace(':', '').split(', ')
    return san

if os.getenv('SHODAN_API', None):
    SHODAN_API=os.environ['SHODAN_API']
else:
    print("Set SHODAN_API ENV")
    sys.exit(1)

api = Shodan(SHODAN_API)
#domain="amorin.org"
domain="wpi.edu"
#domain="amazon.com"
query="ssl.cert.subject.cn:"+domain

TESTING_LOCAL=False
if TESTING_LOCAL:
    try:
        with open("results.pkl","rb") as f:
            results=pickle.load(f)
    except IOError:
        print("File not accessible")
        results=api.search(query)
        pickle.dump(results,open("results.pkl","wb"))
else:
    results=api.search(query)



certlist=[]
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
    }
    certinfo['altnames']=extract_x509_info(service['ssl']['chain'])
    certlist.append(certinfo)

pprint(certlist)



