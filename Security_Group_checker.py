#!/usr/bin/env python3
#Script was developed by Magreef. 
#Main goal of script is to find all security rules with 22 port exposed to 0.0.0.0/0 source.
#Output -- 	SecurityGroupID
#			[InstanceId1,...,instanceIdN][ENIId1,...,ENIIdN] [Tag1,...,TagN] ##Tags from Instance.
#					

import boto3
from nested_lookup import nested_lookup

def check_sg():

    port = 22
    cidr = '0.0.0.0/0'
    client = boto3.client('ec2')
    response_cidr = client.describe_security_groups(
    Filters=[
        {
            'Name': 'ip-permission.from-port',
            'Values': [
                '22',
            ],
        }
    ]
    )
    response_sg = response_cidr['SecurityGroups']
    sgid = []
    for response in response_sg:
        response_sgid = response['GroupId']
        response_sgname = response['GroupName']
        response_ipperm = response['IpPermissions']
        fromport = nested_lookup(key = 'FromPort', document = response_ipperm)
        toport = nested_lookup(key = 'ToPort', document = response_ipperm)
        iprange = nested_lookup(key = 'CidrIp', document = response_ipperm)
        for in_rule in response_ipperm:
            fromport = nested_lookup(key = 'FromPort', document = in_rule)
            toport = nested_lookup(key = 'ToPort', document = in_rule)
            iprange = nested_lookup(key = 'CidrIp', document = in_rule)
            if port in fromport and port in toport and cidr in iprange:
               sgid.append(response_sgid)
    return sgid


def check_instance_ids(sgid):
    instance_ids = []
    client = boto3.client('ec2')
    result = []
    response = client.describe_instances(
      Filters=[
          {
              'Name': 'network-interface.group-id',
              'Values': [
                  sgid,
              ]
          },
      ],
      )
    eni_id = nested_lookup(key = 'NetworkInterfaceId', document = response)
    instance_id = nested_lookup(key = 'InstanceId', document = response)
    tags = nested_lookup(key = 'Tags', document = response)
    result.append(instance_id)
    result.append(eni_id)
    result.append(tags)
    print(result)


def handler():
    sg_list = check_sg()
    for sgid in sg_list:
        print(sgid)
        check_instance_ids(sgid)


handler()