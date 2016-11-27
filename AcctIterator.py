#!/usr/bin/python
#This code accompanies my ImprovedSecAudit.py
#It's intended to iterate through different accounts and generate output for Security Auditors.


import boto3
import botocore
import argparse
import ImprovedSecAudit
import sys

parser = argparse.ArgumentParser(description='Creates security profile of a single AWS account')
parser.add_argument('-a', '--access_key_id', help='AWS access key id')
parser.add_argument('-s', '--secret_access_key', help='AWS secret access key')
parser.add_argument('-t', '--session_token', help ='AWS session token')
parser.add_argument('-r', '--region', help='region to be queried')
parser.add_argument('-v', '--tls_verify', help='False or path to cert bundle for situations where corporate firewalls intercept TLS sessions')
parser.add_argument('-i', '--iam_endpoint', help='Override default IAM endpoint')
parser.add_argument('-S', '--s3_endpoint', help='Override default S3 endpoint')

args = parser.parse_args()
sessparms=dict()
connparms=dict()
if (args.access_key_id is not None) & (args.secret_access_key is not None):
    # sufficient credentials have been passed
    access_key_id = args.access_key_id
    secret_key = args.secret_access_key
    sessparms['aws_access_key_id']=access_key_id
    sessparms['aws_secret_access_key']=secret_key
    # connstr="aws_access_key_id=\"%s\", aws_secret_access_key=\"%s\"" % (access_key_id, secret_key)
    # connstr2='aws_access_key_id=%s, aws_secret_access_key=%s' % (access_key_id,secret_key)
elif (args.session_token is not None):
    session_token = args.session_token
    sessparms['aws_session_token']=session_token
    # connstr="aws_session_token=%s" % session_token
elif ((args.access_key_id is None) & (args.secret_access_key is None)) | (args.session_token is None):
    # insufficient credentials have been passed in
    print("Values for (access_key_id and secret_access_key) or session_token are required")
    # sys.exit()
else:
    print("How did I get here?")
    print(args.access_key_id,"  ",args.secret_access_key,"  ",args.session_token)
if args.region:
    region = args.region
    connparms['region_name']=region
    # connstr = connstr + ", region_name=%s" % region

if args.tls_verify:
    tls_verify = args.tls_verify
    # connstr = connstr + ", verify=%s" % tls_verify
    if (tls_verify == "False") | (tls_verify == "false"):
        connparms['verify']=False
    else:
        connparms['verify']=tls_verify

# print(connstr)
# print(connstr2)
# print(**connparms)
# sess = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key)
# sess=boto3.session.Session(repr(connstr))
sess=boto3.session.Session(**sessparms)
# s3c = sess.client('s3')
# buckets = s3c.list_buckets()
# print(buckets)
# try:
ImprovedSecAudit.sec_audit(sess,connparms)
# except botocore.exceptions.ClientError as e:
#     print(e)
#     if e.response['Error']['Code'] == 'InvalidAccessKeyId':
#         print("Invalid Access Key")




