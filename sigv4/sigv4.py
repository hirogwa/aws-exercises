'''
Exercise to call AWS without SDK.
https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
'''
import argparse
import hashlib
import hmac
import logging
import os
from datetime import datetime

import requests

logging.basicConfig(format='%(asctime)s %(levelname)5s %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)


ALGORITHM = 'AWS4-HMAC-SHA256'


def run(service, action, version, region, host,
        access_key, secret_key, session_token=None,
        with_query_string=False, ssl_verify=True,
        content_type='application/x-www-form-urlencoded'):
    qs = f'Action={action}&Version={version}' if with_query_string else ''
    now = datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    headers = {
        'Content-Type': content_type,
        'Host': host,
        'X-Amz-date': amz_date
    }
    request_payload = ''

    # Task 1: Create a canonical request for Signature Version 4
    canonical_headers = create_canonical_headers(headers)
    signed_headers = create_signed_headers(headers)
    canonical_request = create_canonical_request(qs, canonical_headers, signed_headers, request_payload)

    # Task 2: Create a string to sign for Signature Version 4
    credential_scope = create_credential_scope(datestamp, region, service)
    string_to_sign = create_string_to_sign(amz_date, credential_scope, canonical_request)

    # Task 3: Calculate the signature for AWS Signature Version 4
    signature_key = get_signature_key(secret_key, datestamp, region, service)
    sigv4 = sign(signature_key, string_to_sign, to_hex=True)
    log.debug('Sigv4:%s', sigv4)

    # Task 4: Add the signature to the HTTP request
    req_headers = {
        'Content-Type': content_type,
        'X-Amz-date': amz_date,
        'Authorization': create_authorization_header(access_key, credential_scope, signed_headers, sigv4)
    }
    if session_token:
        req_headers['X-Amz-Security-Token'] = session_token
    log.debug('Headers:%s', req_headers)

    # Do it.
    target_url = f'https://{host}'
    if qs:
        target_url = target_url + '?' + qs
    resp = requests.post(target_url, data=request_payload, headers=req_headers, verify=ssl_verify)
    log.info(resp)
    log.info(resp.text)


def create_authorization_header(access_key, credential_scope, signed_headers, signature):
    return ' '.join([
        ALGORITHM,
        f'Credential={access_key}/{credential_scope},',
        f'SignedHeaders={signed_headers},',
        f'Signature={signature}'
    ])


def create_string_to_sign(amz_date, credential_scope, canonical_request):
    '''https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    '''
    result = '\n'.join([ALGORITHM, amz_date, credential_scope, do_hash(canonical_request)])
    log.debug('String to sign:\n%s', result)
    return result


def create_credential_scope(datestamp, region, service):
    return '/'.join([datestamp, region, service, 'aws4_request'])


def create_canonical_request(
        query_string, canonical_headers, signed_headers, request_payload, method='POST', uri='/'):
    '''https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    '''
    result = '\n'.join([
        method, uri, query_string, canonical_headers, signed_headers, do_hash(request_payload)
    ])
    log.debug('Canonical request:\n%s', result)
    return result


def create_canonical_headers(headers):
    '''Convert headers to a canonical form.
    '''
    return '\n'.join(canonical_header(x, headers[x]) for x in sorted(headers, key=str.lower)) + '\n'


def canonical_header(key, value):
    '''Convert a header to a canonical form.
    '''
    return key.lower() + ':' + value.strip()


def create_signed_headers(headers):
    '''Convert headers to signed headers.
    '''
    return ';'.join(x.lower() for x in sorted(headers, key=str.lower))


def do_hash(x):
    return hashlib.sha256(x.encode('utf-8')).hexdigest()


def sign(key, msg, to_hex=False):
    '''https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    '''
    x = hmac.new(key, msg.encode("utf-8"), hashlib.sha256)
    return x.hexdigest() if to_hex else x.digest()


def get_signature_key(key, datestamp, region_name, service_name):
    '''https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    '''
    k_date = sign(("AWS4" + key).encode("utf-8"), datestamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, "aws4_request")
    return k_signing


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('service', type=str, help='iam for example')
    parser.add_argument('action', type=str, help='ListUsers for example')
    parser.add_argument('version', type=str, help='2010-05-08 for IAM')
    parser.add_argument('region', type=str, help='us-east-1 for example')
    parser.add_argument('host', type=str, help='iam.amazonaws.com for example')
    parser.add_argument('-qs', action='store_true', help='Use query string')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument(
        '--content-type', type=str, default='application/x-www-form-urlencoded',
        help='iam.amazonaws.com for example')

    args = parser.parse_args()
    log.debug(args)

    creds_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    creds_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    creds_session_token = os.environ.get('AWS_SESSION_TOKEN')
    run(args.service, args.action, args.version, args.region, args.host,
        creds_access_key, creds_secret_key, creds_session_token,
        with_query_string=args.qs,
        ssl_verify=not args.no_ssl_verify,
        content_type=args.content_type)
