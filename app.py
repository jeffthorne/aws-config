from __future__ import print_function
import json
import logging

import boto3

from manager import Manager



logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)


def is_instance_protected_by_malware_handler(event, context):
    logger.info('Event: %s' % json.dumps(event))

    compliant = "NON_COMPLIANT"
    host_compliant = False
    params = json.loads(event["ruleParameters"])
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]
    instance_id = configuration_item['resourceId']
    logger.info('InstanceId: %s' % instance_id)
    result = {'annotation': 'AV status to go here'}

    user = params['dsUser']
    password = params['dsPassword']
    tenant = params['dsTenant']

    try:
        dsm = Manager(user, password, tenant)
        host = dsm.does_aws_host_have_malware_turned_on(instance_id)
        if host:
            host_compliant = host.malware_protection_on
            result['annotation'] = host.malware_protection_status
        else:
            host_compliant = False
            result['annotation'] = "Host not found in Deep Security Inventory."

        dsm.end_session()
    except Exception as e:
        print(e)


    if host_compliant:
        compliant = "COMPLIANT"
        result['result'] = 'success'
    else:
        compliant = "NON_COMPLIANT"
        result['result'] = 'failure'


    evaluation = { "compliance_type": compliant, "annotation": result['annotation']}
    config = boto3.client('config')

    response = config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])
    #return compliant