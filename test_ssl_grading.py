import unittest
import sys
import pickle
from sslcert import *
import datetime

"""
Unit tests for :ssl-cert.py
"""
domain="wpi.edu"

class TestStringMethods(unittest.TestCase):
    def test_shodan_load_https_subject(self):
        mysearch = certSearch("SHODAN", "TESTING134", 1)
        mysearch.search(domain, True)
        raw_results = mysearch.get_raw_results()[0]
        cert = {
            'altnames': ['*.echo360.wpi.edu'],
            'cipher': {'bits': 128,
                        'name': 'ECDHE-RSA-AES128-GCM-SHA256',
                        'version': 'TLSv1/SSLv3'},
            'dhparams': {'bits': 4096,
                        'generator': 2,
                        'prime': None,
                        'public_key': None},
            'expired': False,
            'expires': '20220507235959Z',
            'hostname': ['50p2410-echo.echo360.wpi.edu'],
            'ip': '130.215.192.40',
            'isp': 'Worcester Polytechnic Institute',
            'issued': datetime.datetime(2020, 5, 7, 0, 0),
            'pubkey': {'bits': 2048, 'type': 'rsa'},
            'server_cert': None,
            'sig_alg': 'sha256WithRSAEncryption',
            'subject': '*.echo360.wpi.edu',
            'trust_chain': None,
            'version': ['TLSv1', '-SSLv2', '-SSLv3', 'TLSv1.1', 'TLSv1.2', '-TLSv1.3']
        }
        self.assertEquals(raw_results["ssl"]["cert"]["pubkey"]['bits'],cert['pubkey']['bits'])
            
    def test_censys_load_https_subject(self):
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
        #mysearch = certSearch("CENSYS", "TESTING134", "1")
        #mysearch.search(domain, use_cache=True)



if __name__ == '__main__':
    unittest.main()