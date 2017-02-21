from __future__ import print_function
import json
import logging

import boto3

from manager import Manager



logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)


def aws_configrule_handler(event, context):
    logger.info('Event: %s' % json.dumps(event))

    compliant = "NON_COMPLIANT"
    print('yoyo')
    print(event)
    params = json.loads(event["ruleParameters"])
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]

    user = params['dsUser']
    password = params['dsPassword']
    tenant = params['dsTenant']
    print("user:", user)
    print("passwrod:", password)
    print("tenandt:", tenant)

    try:
        print("in try")
        dsm = Manager(user, password, tenant)
        print("api version:", dsm.get_api_version())
        compliant = dsm.antimalware_on("ec2-54-197-177-170.compute-1.amazonaws.com")
        print("session id")
        print(dsm.session_id)
        dsm.end_session()
    except Exception as e:
        print(e)

    result = {'annotation': 'AV status to go here'}
    result['result'] = 'success'

    if compliant:
        compliant = "COMPLIANT"


    evaluation = { "compliance_type": compliant, "annotation": "This resource is compliant with the rule."}
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