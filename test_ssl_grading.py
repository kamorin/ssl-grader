import unittest
import sys
import pickle
import ssl-cert

"""
Unit tests for :ssl-cert.py
"""
domain="wpi.edu"

class TestStringMethods(unittest.TestCase):
    def test_censys_load_https_subject(self):
        # cert_search_results = []
        # print("locading cache")
        # try:
        #     with open(f"{domain}-censys.pkl", "rb") as f:
        #         cert_search_results = pickle.load(f)
        # except IOError as e:
        #     print(f"file not found {e}")
        #     sys.exit(1)

        cert= {
            'altnames': ['w.wpi.edu',
                    'www-backend1.wpi.edu',
                    'www.wpi.edu'],
            'cipher': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'version': 'TLSv1.2'},
            'dhparams': 2048,
            'expired': False,
            'expires': '2022-03-12T23:59:59Z',
            'heartbleed_enabled': None,
            'ip': '130.215.36.26',
            'issued': '2020-03-12T00:00:00Z',
            'pubkey': {'bits': 2048, 'type': 'RSA'},
            'server_cert': None,
            'sig_alg': 'SHA256WithRSA',
            'subject': ['www.wpi.edu'],
            'trust_chain': None,
            'validation': True,
            'validation_reason': True,
            'version': 'TLSv1.2'
        }
        mysearch = certSearch("CENSYS", "TESTING134", "1")
        mysearch.search(domain, use_cache=True)
        
        for certinfo in mysearch.get_results():
            cert = graderCert(**certinfo)
            cert.grade_cert()
            certs.append(cert)
            self.assertEquals(,3)




