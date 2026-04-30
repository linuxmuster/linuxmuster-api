#! /opt/linuxmuster/bin/python3

import argparse
import yaml
import base64
import jwt
import sys
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def jwt_get(user):
    data = lr.get(f'/users/{user}', asdict=False)

    if not data:
        print(f"user {user} not found")
        sys.exit(0)

    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

    secret = base64.b64decode(config['secret'])

    payload  = {
        'user': user,
        'role': data.sophomorixRole,
        'dn': data.dn,
        'school': data.school
    }

    return(jwt.encode(payload, secret, algorithm="HS512"))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='jwtapi',description='JWT for LMNAPI')
    parser.add_argument('user', nargs='?', default='')
    args = parser.parse_args()

    user = args.user

    if not user:
        print("No user given!")
        sys.exit(0)

    print(jwt_get(user))
