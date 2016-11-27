#!/usr/bin/python
# This code was inspired by SecAudit.py
# It has been written from scratch to take advantage of Boto3 functionality
# The ultimate intent for this script is to enable auditing of multiple amazon accounts with significantly reduced labor effort
# Author: Dave Ashby, dave.ashby@potomacsi.com

import boto3
import botocore
import json
import sys

#To-do's:
#Handle the AWS_CA_BUNDLE variable so a certificate bundle containing the internal cert authorities
#Set up code to allow passing in valid session credentials as arguments
#Set up code to allow specifying region(s) to be polled

def main_header(header):
    print("++++++++++++++++++++++ %s ++++++++++++++++++++++" % header)
    print("=====================================================")

def sec_header(header, name):
    print("\n")
    print("====================== %s: %s ======================" % (header, name))

def sub_header(header, name):
    print("---------------------- %s: %s ----------------------" % (header, name))

def pjp(js):
    if type(js) is str:
        print(json.dumps(json.loads(js), sort_keys=True, indent=4))
    else:
        #expects a dict containing json
        print(json.dumps(js,indent=4,sort_keys=True))

def get_iam_roles(iam,conn):

    #Get the roles for the account
    roles = conn.list_roles()
    #Iterate through the roles and retrieve the in-line and attached policies
    sec_header("Roles","")
    for role in roles.get('Roles', None):
        rn = role['RoleName']
        sub_header("Role", rn)
        for rp in iam.Role(rn).policies.all():
            print("In-line Policy: %s" % rp.name)
            pjp(rp.policy_document)
        for ap in iam.Role(rn).attached_policies.all():
            print("Attached Policy: %s" % ap.policy_name)
            pjp(ap.default_version.document)
            print("---------------------------")
        print("\n")

def get_iam_users(iam,conn):
    users = conn.list_users()
    # pjp(users)
    for user in users.get('Users',None):
        un = user['UserName']
        sub_header("User Name", un)
        for policy in iam.User(un).policies.all():
            print("In-line policy: %s" % policy.policy_name)
            pjp(policy.policy_document)
        for policy in iam.User(un).attached_policies.all():
            print("Attached policy: %s" % policy.policy_name)
            pjp (policy.default_version.document)
        for group in iam.User(un).groups.all():
            print("Attached Group: %s" % group.name)
        sub_header("End of User",un)

def get_iam_groups(iam,conn):
    groups = conn.list_groups()
    sec_header("Groups","")
    for group in groups.get('Groups',None):
        gn=group['GroupName']
        sub_header("Group:", gn)
        print("Users:")
        for user in iam.Group(gn).users.all():
            print(user.name)
        for policy in iam.Group(gn).policies.all():
            print("In-line Group Policy: ", policy.policy_name)
            pjp(policy.policy_document)
        for policy in iam.Group(gn).attached_policies.all():
            print("Attached Group Policy: ", policy.policy_name)
            pjp (policy.policy_default_version.document)
        sub_header("End of Group:",gn)
        # print(gn)
        # sec_header("Group", gn)


def get_iam(sess, connparms):
    try:
        # First create IAM resource
        iam = sess.resource('iam', **connparms)
        # Then create an IAM connection from the resource (used for lower-level calls)
        conn = iam.meta.client
        main_header("IAM")
        get_iam_users(iam, conn)
        get_iam_groups(iam, conn)
        get_iam_roles(iam, conn)
    except botocore.exceptions.ClientError as e:
        #need code to handle TLS errors or credential errors
        print("Exception: ",e)
        sys.exit()



def get_s3(sess, connparms):
    try:
        s3r = sess.resource('s3',**connparms)
        s3c = sess.client('s3', **connparms)
        buckets = s3c.list_buckets()
        if buckets:
            main_header("S3")
        for bucket in buckets['Buckets']:
            bn = bucket['Name']
            sec_header("Bucket",bn)
            bnl = s3r.BucketLogging(bn).logging_enabled
            if bnl:
                print("Bucket Logging enabled to ",bnl['TargetBucket'],"with prefix", bnl['TargetPrefix'])
            else:
                print("Bucket Logging is not configured")
            bnv = s3r.BucketVersioning(bn).status
            print("Bucket Versioning: ",bnv)
            try:
                bp=s3r.BucketPolicy(bn).policy
                print("Bucket Policy:")
                pjp(bp)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    print("No Bucket Policy Assigned")
    except botocore.exceptions.ClientError as e:
        print("Exception: ",e)
        sys.exit()

def get_session():
    sess = boto3.session.Session()
    return sess

def sec_audit(sess,connparms):
    get_iam(sess,connparms)
    get_s3(sess,connparms)

if __name__ == '__main__':
    sess=get_session()
    sec_audit(sess,None)


