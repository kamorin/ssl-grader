import sys,os
from shodan import Shodan
from pprint import pprint
import pickle
from OpenSSL import crypto
from datetime import datetime
import certifi
import pem

ROOT_STORE=None


def load_ca_root():
    ''' load all certificates found in openssl cert.pem (via certifi.where())
        
        :return: returns X509store obj loaded with trusted Cert.  
        :rtype: X509store
    '''
    store = crypto.X509Store()
    try:
        with open(certifi.where(), 'rb') as f:
            certs=pem.parse(f.read())
            for cert in certs:
                cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.as_text())
                store.add_cert(cacert)
                print(f"loading root CA store w/ {cacert.get_subject()} ")
    except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
        print(f'No CA Store found at {certifi.where()}, can not validate')
    return store


def extract_x509_info(chain):
    ''' parse PEM formated certificate chain list for v3 extention alt-names

        :param chain: list of PEM certs in UTF-8 string format
        :type chain: list
    '''
    x509cert=crypto.load_certificate(crypto.FILETYPE_PEM, chain[0])
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__().replace('DNS', '').replace(':', '').split(', ')

    print(f"Chain length = {len(chain)}")
    if len(chain)>1:
        verify_chain_of_trust(chain[0], chain[1:])
    return san


def verify_chain_of_trust(cert_pem, trusted_cert_pems):
    '''  openssl manual validation of chain 
        
        :param cert_pem: server cert in PEM UTF-8 string format
        :type cert_pem: str
        :param trusted_cert_pem: list of intermediate certs in PEM UTF-8 string format
        :type trusted_cert_pem: list of str
        :return: return true if chain is verified
        :rtype: bool
    '''
    print(f"\n\n\n***VERIFYING CHAIN OF TRUST****length of intermediate certs = {len(trusted_cert_pems)}")
    #print(cert_pem+"\n\n")

    print("\n\n\nstarting server certification load...")
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    pprint(certificate.get_subject())
    
    for trusted_cert_pem in trusted_cert_pems:
        print("\n\n\nprocessing intermediate cert, adding to store...")
        #pprint(trusted_cert_pem)
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        print(f"{trusted_cert.get_subject()} \n{trusted_cert.get_issuer()} \n")
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
        print("\n\n\nERRRRRRROR!!!!!!\n\n\n\n")
        sys.exit(1)

    if result is None:
        print("\n\n\nVALIDATED!!!!!!\n\n\n\n")
        sys.exit(1)
        return True
    else:
        return False
    


def grade_ssl(cert_list):
    ''' grader 

        :param cert_list: list of dictionaries, each with information on a certificate to grade
        :type cert_list: list of dict
        :return: ...TDB...
        :rtype: ...TDB...
    '''
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



def search(SHODAN_API, query, TESTING_LOCAL=False):
    '''  call Shodan API and process results
    '''
    api = Shodan(SHODAN_API)
    if TESTING_LOCAL:
        try:
            print("\n\n**LOCAL TESTING ENABLED**\nReading cached data from results.pkl\n")
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



if __name__ == "__main__":
    if os.getenv('SHODAN_API', None):
        SHODAN_API=os.environ['SHODAN_API']
    else:
        print("Set SHODAN_API ENV")
        sys.exit(1)

    # load root store    
    ROOT_STORE=load_ca_root()

    #domain="amazon.com"
    domain="wpi.edu"
    query="ssl.cert.subject.cn:"+domain
    TESTING_LOCAL=True

    search(SHODAN_API, query, TESTING_LOCAL)
