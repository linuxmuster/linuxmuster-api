#! /usr/bin/env python3


"""
This script simply generates a self-signed certificate for running linuxmmuster-api.
The certificate will then be located in /etc/linuxmuster/api.

If you want to use your own certificates, just mention it in /etc/linuxmuster/api/config under
uvicorn --> ssl_certfile and ssl_keyfile, and then restart the API.
"""


import sys
import socket
import random
import yaml
from OpenSSL.crypto import dump_certificate, dump_privatekey, FILETYPE_PEM, PKey, TYPE_RSA, X509


etcdir = '/etc/linuxmuster/api'
certificate_path = f'{etcdir}/lmnapi.pem'
config_path = f'{etcdir}/config.yml'

key = PKey()
key.generate_key(TYPE_RSA, 4096)
cert = X509()
cert.get_subject().countryName = 'NA'
cert.get_subject().organizationName = socket.gethostname()
cert.get_subject().commonName = 'lmnapi'
cert.set_pubkey(key)
cert.set_serial_number(random.getrandbits(8 * 20))
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # 10 years
cert.set_issuer(cert.get_subject())
cert.sign(key, 'sha512')

with open(certificate_path, 'wb') as f:
    f.write(dump_privatekey(FILETYPE_PEM, key))
    f.write(dump_certificate(FILETYPE_PEM, cert))
