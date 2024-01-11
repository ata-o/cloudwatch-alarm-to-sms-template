# environment variables:
# SMS_SNS_ARN
# SLACK_URL
# OPSGENIE_SNS_ARN
import boto3
import json
import urllib3
import os

from botocore.exceptions import ClientError


def slack_template(alert_name, reason_message, region, is_recovered):

    status_color = '#007a5a' if is_recovered else '#ff0000'
    title = 'RECOVERED' if is_recovered else 'IN ALARM'

    return {
        "attachments": [
            {
                "color": f"{status_color}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*ALERT STATUS: {title}*"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Region:* {region}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Alert Name:* {alert_name}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Reason:* {reason_message}"
                            }
                        ]
                    }
                ]
            }
        ]
    }


def send_to_slack(alert_name, reason_message, region, is_recovered):
    http = urllib3.PoolManager()

    url = os.environ['SLACK_URL']
    msg = slack_template(alert_name, reason_message, region, is_recovered)
    encoded_msg = json.dumps(msg).encode('utf-8')

    http.request('POST', url, body=encoded_msg, headers={'Content-type': 'application/json'})


def send_to_sns(alert_name, reason_message, region, is_recovered):
    try:
        sns_arn = os.environ['SMS_SNS_ARN']
        aws_region = region
        sns_client = boto3.client('sns')
        sms_message = ok_template().format(aws_region, alert_name) \
            if is_recovered \
            else alarm_template().format(aws_region, alert_name, reason_message)

        sns_client.publish(
            TargetArn=sns_arn,
            Message=sms_message,
        )
        print(sms_message)
    except ClientError as e:
        print(f'An error occured: {e}')
        
def send_to_opsgenie(alert_name, reason_message, region, is_recovered):
    try:
        sns_arn = os.environ['OPSGENIE_SNS_ARN']
        aws_region = region
        sns_client = boto3.client('sns')
        sms_message = ok_template().format(aws_region, alert_name) \
            if is_recovered \
            else alarm_template().format(aws_region, alert_name, reason_message)

        sns_client.publish(
            TargetArn=sns_arn,
            Message=sms_message,
        )
        print(sms_message)
    except ClientError as e:
        print(f'An error occured: {e}')


def ok_template():
    template = """RECOVERED
REGION: {0}
NAME: {1}
"""
    return template


def alarm_template():
    template = """ALERT!
REGION: {0}
NAME: {1}
REASON: {2}
"""
    return template


def format_event(event):
    payload = json.loads(json.dumps(event))['Records'][0]['Sns']
    message = json.loads(payload['Message'])
    return message


def lambda_handler(event, context):
    message = format_event(event)
    alert_name = message['AlarmName']
    new_state_value = message['NewStateValue']
    old_state_value = message['OldStateValue']
    threshold = message['Trigger']['Threshold']
    region = message['Region']
    reason_message = f'Threshold Crossed: {threshold}'

    if new_state_value == 'OK':
        if old_state_value == 'ALARM':
            send_to_sns(alert_name, reason_message, region, is_recovered=True)
            send_to_slack(alert_name, reason_message, region, is_recovered=True)
        else:
            return
    else:
        send_to_sns(alert_name, reason_message, region, is_recovered=False)
        send_to_slack(alert_name, reason_message, region, is_recovered=False)
        send_to_opsgenie(alert_name, reason_message, region, is_recovered=False)
