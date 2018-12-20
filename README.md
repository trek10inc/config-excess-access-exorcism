# IAM Excess Access Exorcist

This config rule uses [IAM Access Advisor][1] to find over-permissioned IAM
users, groups, and roles.

## Deploying

```
# pip install -t IAM_ALLOWS_UNUSED_SERVICES/ boto3 pytz
Installing collected packages: urllib3, six, python-dateutil, jmespath, docutils, botocore, s3transfer, boto3, pytz
Successfully installed boto3-1.9.68 botocore-1.12.68 docutils-0.14 jmespath-0.9.3 python-dateutil-2.7.5 pytz-2018.7 s3transfer-0.1.13 six-1.12.0 urllib3-1.24.1

# rdk -r us-east-2 deploy IAM_ALLOWS_UNUSED_SERVICES
Running deploy!
Zipping IAM_ALLOWS_UNUSED_SERVICES
Uploading IAM_ALLOWS_UNUSED_SERVICES
Upload complete.
Creating CloudFormation Stack for IAM_ALLOWS_UNUSED_SERVICES
Waiting for CloudFormation stack operation to complete...
CloudFormation stack operation complete.
Config deploy complete.
```

## How it Works

The IAM Access Advisor provides a list of services with access history, access
type, and more. The `IAM_ALLOWS_UNUSED_SERVICES` rule looks at the
`LastAuthenticated` field. This has the last time a user used the service, like
this:

```
{
    "ServiceName": "Simple Workflow Service",
    "LastAuthenticated": "2018-08-17-.....",
    "ServiceNamespace": "swf",
    "LastAuthenticatedEntity": ".......",
    "TotalAuthenticatedEntities": 123
}
```



```python
def evaluate_compliance(event, configuration_item, valid_rule_parameters):
    '''Put our custom code in a separate file so it's easier to pack up with our
    rule, or share between multiple rules'''
    import iam_rule_helpers

    iam = get_client('iam', event)

    compliance, annotation = iam_rule_helpers.never_accessed_services_check(iam, configuration_item['configuration']['arn'])
    return build_evaluation_from_config_item(
        configuration_item,
        compliance,
        annotation=annotation
    )
```

[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html
