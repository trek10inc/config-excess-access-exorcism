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


import time


def never_accessed_services_check(iam, arn):
    service_results = get_iam_last_access_details(iam, arn)
    never_accessed = [
        x for x in service_results if 'LastAuthenticated' not in x
    ]
    if len(never_accessed) > 0:
        return (
            'NON_COMPLIANT',
            'Services ' + ', '.join(f"'{x['ServiceNamespace']}'" for x in never_accessed) + ' have never been accessed',
        )
    return 'COMPLIANT', 'IAM entity has accessed all allowed services'


def no_access_in_180_days_check(iam, arn):
    import pytz
    service_results = get_iam_last_access_details(iam, arn)
    utc_now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    older_than_180_days = [
        x for x in service_results
        if 'LastAuthenticated' in x and
        (utc_now - x['LastAuthenticated']) > datetime.timedelta(days=180)
    ]
    if len(older_than_180_days) > 0:
        return (
            'NON_COMPLIANT',
            'Services ' + ', '.join(f"'{x['ServiceNamespace']}'" for x in never_accessed) + ' have not been accessed in the last 180 days',
        )
    return 'COMPLIANT', 'IAM entity has accessed all allowed services in the last 180 days'


def get_iam_last_access_details(iam, arn):
    '''Retrieves IAM last accessed details for the given user/group/role ARN'''
    job = iam.generate_service_last_accessed_details(Arn=arn)
    job_id = job['JobId']
    marker = None
    service_results = []
    while True:
        result = iam.get_service_last_accessed_details(JobId=job_id)
        if result['JobStatus'] == 'IN_PROGRESS':
            print("Awaiting job")
            continue
        elif result['JobStatus'] == 'FAILED':
            raise Exception(f"Could not get access information for {arn}")
        else:
            service_results.extend(paginate_access_details(job_id, result))
            break
        time.sleep(5)
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
