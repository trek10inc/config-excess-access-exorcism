'''
# Usage example - inject this evaluate_complance function into the `rdk` default rule
def evaluate_compliance(event, configuration_item, valid_rule_parameters):
    import iam_rule_helpers

    iam = get_client('iam', event)

    compliance, annotation = iam_rule_helpers.never_accessed_services_check(iam, configuration_item['configuration']['arn'])
    return build_evaluation_from_config_item(
        configuration_item,
        compliance,
        annotation=annotation
    )
'''

import time, redo


def never_accessed_services_check(iam, arn):
    service_results = get_iam_last_access_details(iam, arn)
    never_accessed = [
        x for x in service_results
        if 'LastAuthenticated' not in x
    ]

    if len(never_accessed) == 0:
        return 'COMPLIANT', 'IAM entity has accessed all allowed services'

    policies_by_service = iam.list_policies_granting_service_access(
        Arn=arn, ServiceNamespaces=[s['ServiceNamespace'] for s in never_accessed]
    )['PoliciesGrantingServiceAccess']

    never_accessed_and_not_readonly = [
        g for g in policies_by_service
        if not all(p['PolicyName'] == 'ReadOnlyAccess' for p in g['Policies'])
    ]

    if len(never_accessed_and_not_readonly) > 0:
        return (
            'NON_COMPLIANT',
            "Services " + ', '.join(x['ServiceNamespace'] for x in never_accessed_and_not_readonly)[:220] + " have never been accessed"
        )

    return 'COMPLIANT', 'IAM entity has accessed all allowed services'


def no_access_in_180_days_check(iam, arn):
    import pytz

    service_results = get_iam_last_access_details(iam, arn)

    utc_now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)

    older_than_180_days = [
        x for x in service_results
        if 'LastAuthenticated' in x and (utc_now - x['LastAuthenticated']) > datetime.timedelta(days=180)
    ]
    if len(older_than_180_days) > 0:
        return (
            'NON_COMPLIANT',
            "Services " + ', '.join(f"'{x['ServiceNamespace']}'" for x in never_accessed) + " have not been accessed in the last 180 days",
        )

    return 'COMPLIANT', 'IAM entity has accessed all allowed services in the last 180 days'


def get_iam_last_access_details(iam, arn):
    '''Retrieves IAM last accessed details for the given user/group/role ARN'''
    job = redo.retry(iam.generate_service_last_accessed_details, attempts=5, sleeptime=5, kwargs={'Arn':arn})
    job_id = job['JobId']
    marker = None
    service_results = []
    tries = 0

    while True:
        result = redo.retry(iam.get_service_last_accessed_details, attempts=5, sleeptime=5, kwargs={'JobId': job_id})
        if result['JobStatus'] == 'IN_PROGRESS':
            print("Awaiting job")
        elif result['JobStatus'] == 'FAILED':
            raise Exception(f"Could not get access information for {arn}")
        else:
            service_results.extend(paginate_access_details(job_id, result))
            break
        time.sleep(10)
    return service_results


def paginate_access_details(job_id, result):
    more_data, marker = result['IsTruncated'], result.get('Marker')
    if not more_data:
        return result['ServicesLastAccessed']

    all_service_info = result['ServicesLastAccessed'][:]
    while more_data:
        page = iam.get_service_last_accessed_details(JobId=job['JobId'], Marker=marker)
        more_data, marker = page['IsTruncated'], page['Marker']
        all_service_info.extend(page['ServicesLastAccessed'])
    return all_service_info
