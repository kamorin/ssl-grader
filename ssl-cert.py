import sys,os
from shodan import Shodan
from pprint import pprint
import pickle
from OpenSSL import crypto
from datetime import datetime
import certifi

# crypto is a bit harder to work with vs. OpenSSL, but has more functionality.
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.general_name import DNSName


def load_ca_root():
    ''' load CAs trusted root '''
    store = crypto.X509Store()
    try:
        with open(certifi.where(), 'rb') as f:
            cacert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            store.add_cert(cacert)
            pprint(cacert.get_subject())
            pprint(cacert.get_serial_number())
    except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
        print(f'No CA Store found at {certifi.where()}, can not validate')
    return store


def extract_x509_info_via_crypto(chain):
    ''' parse PEM formated certificate chain list for v3 extention alt-names'''
    chain_info={}
    cert_obj = x509.load_pem_x509_certificate(str.encode(chain), default_backend())
    common_name = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    chain_info['cn']=common_name
    san = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_dns_names = san.value.get_values_for_type(DNSName)
    chain_info['altnames']=san_dns_names
    return chain_info


def extract_x509_info(chain):
    ''' parse PEM formated certificate chain list for v3 extention alt-names'''
    x509cert=crypto.load_certificate(crypto.FILETYPE_PEM, chain[0])
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__().replace('DNS', '').replace(':', '').split(', ')
    
    print("test={}".format(len(chain)))
    #pprint(chain)
    if len(chain)>1:
        #pprint(chain)
        verify_chain_of_trust(chain[0], chain[1:])
        sys.exit(1)
    return san


def verify_chain_of_trust(cert_pem, trusted_cert_pems):
    '''  openssl manual validation of chain '''
    
    print("length of trusted = {}".format(len(trusted_cert_pems)))
    print(trusted_cert_pems)
    print("type={}".format(type(trusted_cert_pems)))
    #pprint(f"trusted crt {len(trusted_cert_pems)}")

    print("starting validation!!!!\n\n\n")
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    pprint(certificate.get_subject())
    print("loaded client!!!!\n\n\n")

    # Create and fill a X509Sore with trusted certs
    store = load_ca_root()

    for trusted_cert_pem in trusted_cert_pems[::-1]:
        #pprint(trusted_cert_pem)
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        print(f"{trusted_cert.get_subject()} \n{trusted_cert.get_issuer()} \n {trusted_cert.get_notAfter()}")
        #trusted_cert.get_issuer()
        #get_notAfter()

        store.add_cert(trusted_cert)
        print("adding trusted_certs!!!\n\n\n")
    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)

    # Returns None if certificate can be validated
    result=None
    try:
        result = store_ctx.verify_certificate()
    except Exception as e:
        print('exception occurred, value:', e)
        result=False

    if result is None:
        return True
    else:
        return False


def grade_ssl(cert_list):
    for cert in cert_list:
        #pprint(cert['sig_alg'])
        warning=False
        if cert['sig_alg'] != 'sha256WithRSAEncryption':
            print(f"WARNING signature algorith weak {cert['sig_alg']}")
            warning=True

        # dhparams': {'bits': 4096,
        # ECDHE enable forward secrecy with modern web browsers

        print(f"{cert['cipher']}")
        if 'RSA' not in cert['cipher']['name']   \
                or 'ADH' in cert['cipher']['name']  \
                or 'CBC' in cert['cipher']['name']  \
                or 'RC4' in cert['cipher']['name']  \
                or 'TLS-RSA' in cert['cipher']['name']:
            print(f"WARNING bad cipher {cert['cipher']}")
            print('Since Cipher Block Chaining (CBC) ciphers were marked as weak (around March 2019) many, many sites now show a bunch of weak ciphers enabled and some are even exploitable via Zombie Poodle and Goldendoodle')
            warning=True      

        if cert['pubkey']['bits'] < 2048:
            print(f"WARNING bits={cert['pubkey']['bits']}")
            warning=True
            
        if cert['expired']:
            print("WARNING EXPIRED CERT")
            print(f"{cert['expires']}\n")
            warning=True
            
        if 'SSLv3' in cert['version']:
            print("WARNING SSLv3 SUPPORTED")
            warning=True
        
        if 'TLSv1' in cert['version']:
            print("WARNING TLSv1 SUPPORTED")
            warning=True
        
        if warning:
            # print(f"REVIEW: host={cert['hostname']} alt={cert['altnames']} for issues \n")
            print(f"REVIEW: host={cert['hostname']} for issues \n")


if os.getenv('SHODAN_API', None):
    SHODAN_API=os.environ['SHODAN_API']
else:
    print("Set SHODAN_API ENV")
    sys.exit(1)

api = Shodan(SHODAN_API)
domain="wpi.edu"
#domain="amazon.com"
query="ssl.cert.subject.cn:"+domain

TESTING_LOCAL=True
if TESTING_LOCAL:
    try:
        print("\n\n**Reading cached data from results.pkl\n")
        with open("results.pkl","rb") as f:
            results=pickle.load(f)
    except IOError:
        print("**Cache file not accessible, regening file")
        results=api.search(query)
        pickle.dump(results,open("results.pkl","wb"))
else:
    print(f"**Querying Shodan with Search query {query}\n")
    results=api.search(query)

cert_list=[]
for service in results['matches']:
    #pprint(service)
    #break
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
                }
    print("\n\n\n\n")
    pprint(certinfo)

    certinfo['altnames']=extract_x509_info(service['ssl']['chain'])
    cert_list.append(certinfo)

#grade_ssl(cert_list)
#pprint(cert_list)



