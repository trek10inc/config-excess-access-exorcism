'''
Creates CSV report with noncompliant resources for the IAM_ALLOWS_UNUSED_SERVICES rule 

Usage example:
    python report.py ./report.csv
'''

import boto3
import csv
import sys

UNUSED_SERVICES_ROLE = 'IAM_ALLOWS_UNUSED_SERVICES'
iam = boto3.client('iam')
config = boto3.client('config')

def generate_csv(resources, filepath):
    with open(filepath, 'w', newline='') as csvfile:
        fieldnames = ['resource_name', 'resource_type', 'resource_arn', 'services', 'users']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for resource in resources:
            writer.writerow(resource)

def generate_report():
    try:
        report_filepath = sys.argv[1]
    except:
        report_filepath = './report.csv'
    generate_csv(get_noncompilant_resources(), report_filepath)
    
def get_iam_group_details(resource_name):
    group = iam.get_group(GroupName=resource_name)
    return {'users': list(map(lambda user: user['UserName'], group['Users']))}

def get_noncompilant_resources():
    paginator = config.get_paginator('get_compliance_details_by_config_rule')
    response_iterator = paginator.paginate(
        ConfigRuleName=UNUSED_SERVICES_ROLE,
        ComplianceTypes=['NON_COMPLIANT']
    )
    resources = []
    for response in response_iterator:
        resources += parse_evaluation_results(response['EvaluationResults'])
    return resources

def get_resource_config(resource_id, resource_configs):
    config = next(x for x in resource_configs if x['resourceId'] == resource_id)
    return {
        'resource_name': config['resourceName'],
        'resource_arn': config['arn']
    }

def get_resource_details(resource_name, resource_type):
    resolvers = {
        'AWS::IAM::Group': get_iam_group_details
    }
    try:
        return resolvers[resource_type](resource_name)
    except:
        return {}

def get_resource_dto(resource, resource_configs):
    config = get_resource_config(resource['resource_id'], resource_configs)
    return {
        **resource,
        **config,
        **get_resource_details(config['resource_name'], resource['resource_type'])
    }

def parse_evaluation_results(results):
    resources = list(map(lambda item: {
        'resource_id': item['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
        'resource_type': item['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
        'services': item['Annotation'].replace('Services ','',1).replace(' have never been accessed','').split(', '),
    }, results))

    resource_keys = list(map(lambda item : {
        'resourceType': item['resource_type'],
        'resourceId': item['resource_id']
    }, resources))

    resource_configs = config.batch_get_resource_config(resourceKeys=resource_keys)['baseConfigurationItems']
    return list(map(lambda resource: get_resource_dto(resource, resource_configs), resources))

generate_report()