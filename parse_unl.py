'''
Retrieve and parse a published rippled UNL.
Returns base58 encoded XRP Ledger keys.
'''

import json
from hashlib import sha256
from base64 import b64decode
import requests


def rippled_bs58(key):
    '''
    Returns a string that is encoded using the rippled base58 alphabet.
    '''
    alphabet = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
    string = b""
    while key:
        key, idx = divmod(key, 58)
        string = alphabet[idx:idx+1] + string
    return string

def unl_parser(address='https://vl.ripple.com'):
    '''
    Download the UNL and base64 decode the blob.
    Defaults to https://vl.ripple.com
    Individual validation keys are then constructed from the decoded blob
    payload and the double sha256 hashed checksums. Keys are then base58 encoded.
    '''
    keys = {'status': 'Error',
            'error': False,
            'http_code': '',
            'public_validation_keys': [],
            'expiration': '',}

    try:
        unl = requests.get(address)
        keys['http_code'] = unl.status_code
        unl.raise_for_status()
    except requests.exceptions.RequestException:
        keys['error'] = "Invalid URL: {}.".format(address)
        return json.dumps(keys)

    try:
        blob = json.loads(b64decode(unl.json()['blob']).decode('utf-8'))
        validators = blob['validators']
        '''
        Convert Ripple Epoch to Unix Epoch
        Reference : https://xrpl.org/basic-data-types.html
        '''
        keys['expiration'] = blob['expiration'] + 946684800

    except json.decoder.JSONDecodeError:
        keys['error'] = "Invalid or malformed manifest."
        return json.dumps(keys)

    if not validators:
        keys['error'] = "List of validator keys was empty."
        return json.dumps(keys)

    for i in validators:
        payload = "1C" + i['validation_public_key']
        keys['public_validation_keys'].append(
            rippled_bs58(int(payload + sha256(bytearray.fromhex(sha256(
                bytearray.fromhex(payload)).hexdigest())).hexdigest()[0:8], 16)).decode('utf-8'))

    keys['status'] = 'Success'
    return json.dumps(keys)
